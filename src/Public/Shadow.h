/*
* Copyright (c) 2025 StormWeaver
*
* This file is part of the Kerbecs Address Sanitizer API
*
* Licensed under the MIT License. You may obtain a copy of the License at
* https://opensource.org/licenses/MIT
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND...
*/

#pragma once
#include "Kerbecs.h"
#include "KerbecsEnforcements.h"
#include "KerbecsStats.h"
#include "KerbecsChecksums.h"
#include "AllocationRegistry.h"
#include "ShadowUtils.h"
#include "Violation.h"
#include "MemoryZone.h"
#include "MemorySupport.h"

#include <cstdint>

namespace Kerbecs::Shadow {
	template<typename L, typename S, typename O, typename H, typename AC>
		requires Enforcement::LayoutPolicyConcept<L>
	&& Enforcement::ShadowMapConcept<S>
		&& Enforcement::LoggerConcept<O>
		&& Enforcement::HashAccumulatorConcept<H>
		&& Enforcement::AllocatorConcept<AC>
		struct KERBECS_RUNTIME_API Shadow {
		private:
			using layout_ = L;
			using shadow_ = S;
			using logger_ = O;
			using hasher_ = H;
			using allocator_ = AC;
		public:
			void* m_RawPtr = nullptr; // start of user payload
			void* m_BlockBase = nullptr; // start of raw heap block
			size_t                    m_TotalSize = 0;       // total heap block size
			size_t					  m_UserSize = 0;		// total user size
			layout_::Offsets m_Offsets = {};      // layout-computed offsets
			shadow_* m_Map = nullptr; // injected shadow bitmap
			logger_* m_Logger = nullptr; // injected violation logger
			hasher_* m_Hasher = nullptr; // injected hash accumulator
			const char* m_Name = nullptr; // debug tag (string literal, not owned)
			uint64_t                  m_AllocID = 0;       // allocator identity hash
			uint32_t                  m_ThreadID = 0;       // allocating thread ID
			StackTrace                m_AllocTrace = {};      // allocation call site
			StackTrace                m_FreeTrace = {};      // free call site
			// Non-owning pointer to the MemorySupport wrapper for this shadow's
			// allocator. Shadow fires a violation if this is null at destroy time.
			Internal::MemorySupport<AC>* m_UserAllocator = nullptr;
	};

	template<typename LP, typename SM, typename LG, typename HA, typename AC>
	KERBECS_FORCEINLINE void _reportViolation(
		const Shadow<LP, SM, LG, HA, AC>* p_Shadow,
		ViolationKind                  v_Kind,
		void* p_FaultAddr) noexcept {
		statsOnViolation(&MemoryZone::instance().m_Stats);

		if (!p_Shadow->m_Logger) return;

		Violation v{};
		v.m_Kind = v_Kind;
		v.m_Name = p_Shadow->m_Name;
		v.m_Address = p_FaultAddr;
		v.m_BlockBase = p_Shadow->m_BlockBase;
		v.m_BlockSize = p_Shadow->m_TotalSize;
		v.m_AllocSite = p_Shadow->m_AllocTrace;
		v.m_FreeSite = p_Shadow->m_FreeTrace;
		v.m_ThreadID = p_Shadow->m_ThreadID;

#ifdef _WIN32
		v.m_Timestamp = __rdtsc();
#else
		v.m_Timestamp = 0;
#endif

		p_Shadow->m_Logger->submit(v);
	}

	template<typename LP, typename SM, typename LG, typename HA, typename AC>
	KERBECS_FORCEINLINE void shadowRawFill(
		Shadow<LP, SM, LG, HA, AC>* p_Shadow,
		size_t v_Offset, size_t v_Length, uint8_t v_Value) noexcept {
		std::memset(static_cast<std::byte*>(p_Shadow->m_BlockBase) + v_Offset, v_Value, v_Length);
	}

	template<typename LP, typename SM, typename LG, typename HA, typename AC>
	void shadowPoison(Shadow<LP, SM, LG, HA, AC>* p_Shadow, size_t v_Offset, size_t v_Length) noexcept {
		shadowRawFill(p_Shadow, v_Offset, v_Length, static_cast<uint8_t>(MemoryZone::POISONED));
		void* userPtr = static_cast<std::byte*>(p_Shadow->m_BlockBase) + v_Offset;
		MemoryZone::shadowPoison(userPtr, v_Length);
		if (p_Shadow->m_Map)
			p_Shadow->m_Map->poison(userPtr, v_Length);
		statsOnPoison(&MemoryZone::instance().m_Stats, v_Length);
	}

	template<typename LP, typename SM, typename LG, typename HA, typename AC>
	void shadowUnpoison(Shadow<LP, SM, LG, HA, AC>* p_Shadow, size_t v_Offset, size_t v_Length) noexcept {
		shadowRawFill(p_Shadow, v_Offset, v_Length, static_cast<uint8_t>(MemoryZone::UNPOISONED));
		void* userPtr = static_cast<std::byte*>(p_Shadow->m_BlockBase) + v_Offset;
		MemoryZone::shadowUnpoison(userPtr, v_Length);
		if (p_Shadow->m_Map)
			p_Shadow->m_Map->unpoison(userPtr, v_Length);
		statsOnUnpoison(&MemoryZone::instance().m_Stats, v_Length);
	}

	template<typename LP, typename SM, typename LG, typename HA, typename AC>
	void shadowRedzone(Shadow<LP, SM, LG, HA, AC>* p_Shadow, size_t v_Offset, size_t v_Length) noexcept {
		shadowRawFill(p_Shadow, v_Offset, v_Length, static_cast<uint8_t>(MemoryZone::REDZONE));
	}

	template<typename LP, typename SM, typename LG, typename HA, typename AC>
	void shadowDeRedzone(Shadow<LP, SM, LG, HA, AC>* p_Shadow, size_t v_Offset, size_t v_Length) noexcept {
		shadowRawFill(p_Shadow, v_Offset, v_Length, 0);
	}

	template<typename LP, typename SM, typename LG, typename HA, typename AC>
	void shadowTombstone(Shadow<LP, SM, LG, HA, AC>* p_Shadow, size_t v_Offset, size_t v_Length) noexcept {
		shadowRawFill(p_Shadow, v_Offset, v_Length, static_cast<uint8_t>(MemoryZone::TOMBSTONE));
		void* userPtr = static_cast<std::byte*>(p_Shadow->m_BlockBase) + v_Offset;
		MemoryZone::shadowPoison(userPtr, v_Length);
		if (p_Shadow->m_Map)
			p_Shadow->m_Map->poison(userPtr, v_Length);
	}

	template<typename LP, typename SM, typename LG, typename HA, typename AC>
	KERBECS_NODISCARD_MSG("Cannot discard shadow state")
		Utils::MemoryState shadowStateOf(
			const Shadow<LP, SM, LG, HA, AC>* p_Shadow,
			size_t v_Offset, size_t v_Size) noexcept {
		if (!p_Shadow || !p_Shadow->m_BlockBase || !p_Shadow->m_Map)
			return Utils::MemoryState::CORRUPTED;

		void* userPtr = static_cast<std::byte*>(p_Shadow->m_BlockBase) + v_Offset;

		size_t poisoned = p_Shadow->m_Map->countPoisoned(userPtr, v_Size);
		if (poisoned == v_Size)                return Utils::MemoryState::UNINITIALIZED;
		if (poisoned > 0 && poisoned < v_Size) return Utils::MemoryState::CORRUPTED;
		if (Utils::verifyTombstone(userPtr, v_Size)) return Utils::MemoryState::DESTROYED;

		return Utils::MemoryState::CONSTRUCTED;
	}

	template<typename LP, typename SM, typename LG, typename HA, typename AC>
	KERBECS_MAYBE_UNUSED bool shadowVerifyGuards(const Shadow<LP, SM, LG, HA, AC>* p_Shadow) noexcept {
		if (!p_Shadow || !p_Shadow->m_BlockBase) return false;
		return LP::verifyGuards(p_Shadow->m_BlockBase, p_Shadow->m_Offsets, p_Shadow->m_TotalSize);
	}

	template<typename T, typename LP, typename SM, typename LG, typename HA, typename AC>
	KERBECS_MAYBE_UNUSED bool shadowAllocate(
		Shadow<LP, SM, LG, HA, AC>* p_Shadow,
		size_t v_Count = 1) noexcept {
		if (!p_Shadow) return false;

		if (!p_Shadow->m_UserAllocator) {
			_reportViolation(p_Shadow, ViolationKind::WildPointer, nullptr);
			return false;
		}

		if (v_Count > SIZE_MAX / sizeof(T)) return false;

		size_t payloadSize = v_Count * sizeof(T);
		size_t blockSize = LP::blockSize(payloadSize, alignof(T));

		void* block = p_Shadow->m_UserAllocator->allocate(blockSize, alignof(std::max_align_t));

		if (!block) return false;
		p_Shadow->m_UserSize = payloadSize;
		return shadowInit<T>(
			p_Shadow,
			block,
			blockSize,
			v_Count);
	}

	template<typename T, typename LP, typename SM, typename LG, typename HA, typename AC>
	KERBECS_MAYBE_UNUSED bool shadowInit(Shadow<LP, SM, LG, HA, AC>* p_Shadow, void* p_Block, size_t v_BlockSize, size_t v_Count = 1) noexcept {
		if (!p_Shadow || !p_Block) return false;
		if (v_Count > SIZE_MAX / sizeof(T)) return false;

		// ---- Stamp allocating thread ID ----
		p_Shadow->m_ThreadID = Tracing::Internal::currentThreadID();

		const size_t payloadSize = v_Count * sizeof(T);
		const size_t requiredSize = LP::blockSize(payloadSize, alignof(T));
		if (v_BlockSize < requiredSize) return false;

		// ---- Layout Placement (block-relative) ----
		p_Shadow->m_Offsets = LP::place(p_Block, v_BlockSize, payloadSize, alignof(T));

		p_Shadow->m_BlockBase = p_Block;
		p_Shadow->m_TotalSize = v_BlockSize;
		p_Shadow->m_UserSize = payloadSize;

		// ---- Derive Payload Pointer ----
		auto* payload = static_cast<std::byte*>(p_Block) + p_Shadow->m_Offsets.m_UserDataOffset;

		// ---- Alignment Check (on payload, NOT block base) ----
		if (reinterpret_cast<uintptr_t>(payload) % alignof(T) != 0) {
			_reportViolation(p_Shadow,
							 ViolationKind::AlignmentViolation,
							 payload);
			return false;
		}

		p_Shadow->m_RawPtr = payload;

		// ---- Metadata Initialization (block-relative) ----
		if constexpr (requires { p_Shadow->m_Offsets.m_MetaDataOffsetLeading; }) {
			if (p_Shadow->m_Hasher) {
				auto* leading =
					reinterpret_cast<MemoryZone::EnhancedMetaData*>(
						static_cast<std::byte*>(p_Block)
						+ p_Shadow->m_Offsets.m_MetaDataOffsetLeading);

				auto* trailing =
					reinterpret_cast<MemoryZone::EnhancedMetaData*>(
						static_cast<std::byte*>(p_Block)
						+ p_Shadow->m_Offsets.m_MetaDataOffsetTrailing);

				Checksums::initEnhancedMetadata(
					p_Shadow->m_Hasher,
					leading,
					trailing,
					v_BlockSize,
					p_Shadow->m_AllocID,
					static_cast<uint64_t>(p_Shadow->m_ThreadID),
					p_Block);
			}
		} else if constexpr (requires { p_Shadow->m_Offsets.m_MetaDataOffset; }) {
			auto* meta =
				reinterpret_cast<MemoryZone::NormalMetaData*>(
					static_cast<std::byte*>(p_Block)
					+ p_Shadow->m_Offsets.m_MetaDataOffset);

			Checksums::initNormalMetadata(
				meta,
				v_BlockSize,
				p_Shadow->m_AllocID);
		}

		// ---- Initial Poison (payload region only, block-relative offset) ----
		shadowPoison(
			p_Shadow,
			p_Shadow->m_Offsets.m_UserDataOffset,
			payloadSize);

		// ---- Registry Insert ----
		auto& zone = MemoryZone::instance();

		if (zone.m_Initialized) {
			const bool inserted =
				zone.m_Registry.insert(
					p_Block,
					payload,
					v_BlockSize,
					payloadSize,
					p_Shadow->m_AllocID,
					p_Shadow->m_ThreadID,
					p_Shadow->m_Name,
					p_Shadow->m_AllocTrace,
					v_Count);

			if (!inserted) {
				_reportViolation(
					p_Shadow,
					ViolationKind::OverlapDetected,
					p_Block);

				return false;
			}

			statsOnInit(&zone.m_Stats, v_BlockSize);
		}
		return true;
	}

	template<typename T, typename LP, typename SM, typename LG, typename HA, typename AC, typename... Args>
	KERBECS_MAYBE_UNUSED bool shadowConstruct(
		Shadow<LP, SM, LG, HA, AC>* p_Shadow, Args&&... u_Args) noexcept {
		if (!p_Shadow || !p_Shadow->m_RawPtr) return false;

		if (reinterpret_cast<uintptr_t>(p_Shadow->m_RawPtr) % alignof(T) != 0) {
			_reportViolation(p_Shadow, ViolationKind::AlignmentViolation, p_Shadow->m_RawPtr);
			return false;
		}

		shadowUnpoison(p_Shadow, p_Shadow->m_Offsets.m_UserDataOffset, sizeof(T));
		::new (p_Shadow->m_RawPtr) T(std::forward<Args>(u_Args)...);
		return true;
	}

	template<typename T, typename LP, typename SM, typename LG, typename HA, typename AC, typename... Args>
	KERBECS_MAYBE_UNUSED bool shadowConstructAt(
		Shadow<LP, SM, LG, HA, AC>* p_Shadow, size_t v_Idx, Args&&... u_Args) noexcept {
		if (!p_Shadow || !p_Shadow->m_RawPtr) return false;

		size_t offset = v_Idx * sizeof(T);
		void* loc = static_cast<std::byte*>(p_Shadow->m_RawPtr) + offset;

		if (reinterpret_cast<uintptr_t>(loc) % alignof(T) != 0) {
			_reportViolation(p_Shadow, ViolationKind::AlignmentViolation, loc);
			return false;
		}

		shadowUnpoison(p_Shadow, p_Shadow->m_Offsets.m_UserDataOffset + offset, sizeof(T));
		::new (loc) T(std::forward<Args>(u_Args)...);
		return true;
	}

	template<typename T, typename LP, typename SM, typename LG, typename HA, typename AC>
	KERBECS_MAYBE_UNUSED bool shadowDestroy(
		Shadow<LP, SM, LG, HA, AC>* p_Shadow,
		size_t v_Idx = 0) noexcept {
		if (!p_Shadow || !p_Shadow->m_RawPtr) return false;

		// ---- Allocator null check - Shadow owns this violation ----
		if (!p_Shadow->m_UserAllocator) {
			_reportViolation(p_Shadow, ViolationKind::WildPointer, p_Shadow->m_BlockBase);
			return false;
		}

		// ---- Thread ownership check (must be called from allocating thread) ----
		if (Tracing::Internal::currentThreadID() != p_Shadow->m_ThreadID) {
			_reportViolation(p_Shadow, ViolationKind::ThreadOwnership, p_Shadow->m_BlockBase);
			return false;
		}

		size_t             offset = p_Shadow->m_Offsets.m_UserDataOffset + v_Idx * sizeof(T);
		Utils::MemoryState state = shadowStateOf(p_Shadow, offset, sizeof(T));

		if (state == Utils::MemoryState::DESTROYED) {
			_reportViolation(p_Shadow, ViolationKind::DoubleFree,
							 static_cast<std::byte*>(p_Shadow->m_BlockBase) + offset);
			return false;
		}
		if (state == Utils::MemoryState::UNINITIALIZED) {
			_reportViolation(p_Shadow, ViolationKind::UseBeforeInit,
							 static_cast<std::byte*>(p_Shadow->m_BlockBase) + offset);
			return false;
		}
		if (state == Utils::MemoryState::CORRUPTED) {
			_reportViolation(p_Shadow, ViolationKind::MetadataCorruption,
							 static_cast<std::byte*>(p_Shadow->m_BlockBase) + offset);
			return false;
		}

		if constexpr (requires { p_Shadow->m_Offsets.m_MetaDataOffsetLeading; }) {
			if (p_Shadow->m_Hasher) {
				auto* leading = reinterpret_cast<MemoryZone::EnhancedMetaData*>(
					static_cast<std::byte*>(p_Shadow->m_BlockBase) + p_Shadow->m_Offsets.m_MetaDataOffsetLeading);
				auto* trailing = reinterpret_cast<MemoryZone::EnhancedMetaData*>(
					static_cast<std::byte*>(p_Shadow->m_BlockBase) + p_Shadow->m_Offsets.m_MetaDataOffsetTrailing);

				if (!Checksums::verifyEnhancedMetadata(
					p_Shadow->m_Hasher,
					leading, trailing,
					p_Shadow->m_TotalSize,
					p_Shadow->m_AllocID,
					static_cast<uint64_t>(p_Shadow->m_ThreadID),
					p_Shadow->m_BlockBase,
					Utils::ThreadPolicy::Strict)) {
					_reportViolation(p_Shadow, ViolationKind::MetadataCorruption, p_Shadow->m_BlockBase);
				}
			}
		} else if constexpr (requires { p_Shadow->m_Offsets.m_MetaDataOffset; }) {
			auto* meta = reinterpret_cast<MemoryZone::NormalMetaData*>(
				static_cast<std::byte*>(p_Shadow->m_BlockBase) + p_Shadow->m_Offsets.m_MetaDataOffset);

			if (!Checksums::verifyNormalMetadata(meta, p_Shadow->m_TotalSize, p_Shadow->m_AllocID))
				_reportViolation(p_Shadow, ViolationKind::MetadataCorruption, p_Shadow->m_BlockBase);
		}

		if (!shadowVerifyGuards(p_Shadow))
			_reportViolation(p_Shadow, ViolationKind::BufferOverflow, p_Shadow->m_BlockBase);

		auto& zone = MemoryZone::instance();

		// ---- Derive type-erased allocator/thunk from m_UserAllocator ----
		void* allocatorPtr = static_cast<void*>(p_Shadow->m_UserAllocator);
		void (*thunk)(void*, void*, size_t) = &Internal::MemorySupport<AC>::thunk;

		// ---- Begin retiring cycle - CAS Live -> Retiring, acquires dtor lock ----
		Tracing::Internal::RegistryNode* node = nullptr;
		if (zone.m_Initialized && p_Shadow->m_BlockBase) {
			node = zone.m_Registry.beginRetiring(
				p_Shadow->m_BlockBase,
				p_Shadow->m_ThreadID);

			if (!node) {
				// tryLock failed - concurrent dtor attempt on same block.
				_reportViolation(p_Shadow, ViolationKind::ThreadOwnership, p_Shadow->m_BlockBase);
				return false;
			}
		}

		void* loc = static_cast<std::byte*>(p_Shadow->m_BlockBase) + offset;
		static_cast<T*>(loc)->~T();

		shadowTombstone(p_Shadow, offset, sizeof(T));

		// ---- Decrement live count for this destroyed object ----
		if (node)
			node->m_LiveCount.fetch_sub(1, std::memory_order_acq_rel);

		if (zone.m_Initialized && p_Shadow->m_BlockBase) {
			const uint64_t epoch = zone.m_Epoch.load(std::memory_order_acquire);

			zone.m_Registry.endRetiring(
				p_Shadow->m_BlockBase,
				epoch,
				allocatorPtr,
				thunk);

			// If the node transitioned to Quarantine, enqueue it.
			if (node) {
				const auto nodeState = node->m_State.load(std::memory_order_acquire);
				if (nodeState == Tracing::Internal::AllocationState::Quarantine) {
					KERBECS_UNUSED(zone.m_Quarantine.enqueue(
						p_Shadow->m_BlockBase,
						p_Shadow->m_TotalSize,
						epoch,
						allocatorPtr,
						thunk));
				}
			}

			statsOnDestroy(&zone.m_Stats);
		}

		return true;
	}

	template<typename T, typename LP, typename SM, typename LG, typename HA, typename AC>
	KERBECS_NODISCARD_MSG("Cannot discard shadow state")
		Utils::MemoryState shadowGetMemoryState(
			const Shadow<LP, SM, LG, HA, AC>* p_Shadow,
			size_t v_Index = 0) noexcept {
		if (!p_Shadow || !p_Shadow->m_BlockBase)
			return Utils::MemoryState::CORRUPTED;

		// ---- Compute block-relative offset ----
		const size_t offset = p_Shadow->m_Offsets.m_UserDataOffset + v_Index * sizeof(T);

		// ---- Compute payload pointer for registry check ----
		void* payloadAddr =
			static_cast<std::byte*>(p_Shadow->m_BlockBase) + offset;

		auto& zone = MemoryZone::instance();

		if (zone.m_Initialized) {
			const Tracing::Internal::RegistryNode* node =
				zone.m_Registry.findRange(p_Shadow->m_BlockBase, payloadAddr);

			if (!node) {
				// Either wild pointer or already retired block
				_reportViolation(
					const_cast<Shadow<LP, SM, LG, HA, AC>*>(p_Shadow),
					ViolationKind::WildPointer,
					payloadAddr);

				return Utils::MemoryState::CORRUPTED;
			}

			auto state = node->m_State.load(std::memory_order_acquire);

			if (state == Tracing::Internal::AllocationState::Retiring) {
				// Dtor cycle is in progress on this block. Only the thread
				// that won m_DtorLock may access it. All others fail fast.
				if (Tracing::Internal::currentThreadID() != node->m_ThreadID) {
					_reportViolation(
						const_cast<Shadow<LP, SM, LG, HA, AC>*>(p_Shadow),
						ViolationKind::RetiredBoundaryViolation,
						payloadAddr);
					KERBECS_TRAP();
				}
			}

			if (state == Tracing::Internal::AllocationState::Quarantine) {
				_reportViolation(
					const_cast<Shadow<LP, SM, LG, HA, AC>*>(p_Shadow),
					ViolationKind::UseAfterFree,
					payloadAddr);

				return Utils::MemoryState::DESTROYED;
			}
		}

		// ---- Shadow state check (block-relative) ----
		Utils::MemoryState state =
			shadowStateOf(p_Shadow, offset, sizeof(T));

		if (state != Utils::MemoryState::CONSTRUCTED)
			return state;

		// ---- Guard verification ----
		if (!shadowVerifyGuards(p_Shadow)) {
			_reportViolation(
				const_cast<Shadow<LP, SM, LG, HA, AC>*>(p_Shadow),
				ViolationKind::BufferOverflow,
				p_Shadow->m_BlockBase);

			return Utils::MemoryState::CORRUPTED;
		}
		return Utils::MemoryState::CONSTRUCTED;
	}

	template<typename T, typename LP, typename SM, typename LG, typename HA, typename AC>
	KERBECS_NODISCARD_MSG("Cannot discard shadow state")
		Utils::MemoryState shadowVerifyBlockState(
			const Shadow<LP, SM, LG, HA, AC>* p_Shadow, size_t v_Count) noexcept {
		for (size_t i = 0; i < v_Count; i++) {
			Utils::MemoryState s = shadowGetMemoryState<T>(p_Shadow, i);
			if (s != Utils::MemoryState::DESTROYED) return s;
		}
		return Utils::MemoryState::DESTROYED;
	}

	template<typename T, typename LP, typename SM, typename LG, typename HA, typename AC>
	void shadowPoisonObject(Shadow<LP, SM, LG, HA, AC>* p_Shadow, size_t v_Index = 0) noexcept {
		shadowPoison(p_Shadow, p_Shadow->m_Offsets.m_UserDataOffset + v_Index * sizeof(T), sizeof(T));
	}

	template<typename T, typename LP, typename SM, typename LG, typename HA, typename AC>
	void shadowUnpoisonObject(Shadow<LP, SM, LG, HA, AC>* p_Shadow, size_t v_Index = 0) noexcept {
		shadowUnpoison(p_Shadow, p_Shadow->m_Offsets.m_UserDataOffset + v_Index * sizeof(T), sizeof(T));
	}

	template<typename T, typename LP, typename SM, typename LG, typename HA, typename AC>
	void shadowTombstoneObject(Shadow<LP, SM, LG, HA, AC>* p_Shadow, size_t v_Index = 0) noexcept {
		shadowTombstone(p_Shadow, p_Shadow->m_Offsets.m_UserDataOffset + v_Index * sizeof(T), sizeof(T));
	}
}