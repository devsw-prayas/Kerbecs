/*
* Copyright (c) 2025 StormWeaver
*
* This file is part of the Kerbecs Address Sanitizer API
*
* Licensed under the MIT License. You may obtain a copy of the License at
* https://opensource.org/licenses/MIT
*/

#pragma once
#include "AllocationRegistry.h"
#include "KerbecsEnforcements.h"
#include "KerbecsMemory.h"
#include "KerbecsRuntime.h"
#include "MemoryLayouts.h"
#include "MemorySupport.h"
#include "RegionRecord.h"
#include "ShadowUtils.h"
#include "ShadowedMemory.h"
#include <utility>
namespace Kerbecs {

	template<typename LayoutT, Shadow::Utils::ThreadPolicy ThreadPolicyT, typename AllocatorT>
		requires Enforcement::LayoutPolicyConcept<LayoutT> && Enforcement::AllocatorConcept<AllocatorT>
	class Region final {
	public:
		Region(
			AllocatorT& p_Allocator,
			size_t v_Size,
			size_t v_AllocationRegistryCapacity,
			void* p_RegionBase = nullptr) noexcept
			: m_Allocator(p_Allocator)
			, m_Size(v_Size)
			, m_RegionBase(p_RegionBase)
			, m_AllocatorSupport(&p_Allocator)
			, m_AllocationRegistry(v_AllocationRegistryCapacity) {
			if (v_Size == 0 || v_AllocationRegistryCapacity == 0)
				return;

			auto& runtime = Runtime::instance();
			if (!runtime.init())
				return;

			const size_t shadowBytes = (v_Size + ((size_t{ 1 } << Runtime::SHADOW_SCALE) - 1))
				>> Runtime::SHADOW_SCALE;
			if (shadowBytes == 0 ||
				v_AllocationRegistryCapacity >
					std::numeric_limits<size_t>::max() / sizeof(Runtime::AccessInfo))
				return;

			m_ShadowBlobPtr = runtime.shadowzoneAllocate(shadowBytes);
			m_MetadataMapBase = runtime.metadataZoneAllocate(
				v_AllocationRegistryCapacity * sizeof(Runtime::AccessInfo),
				alignof(Runtime::AccessInfo));

			if (!m_ShadowBlobPtr || !m_MetadataMapBase)
				return;

			if (!m_AllocationRegistry.init())
				return;

			m_Initialized = runtime.registerRegion(
				this,
				m_ShadowBlobPtr,
				m_MetadataMapBase,
				m_Size,
				m_RegionBase);
		}

		~Region() {
			// Flush shared QuarantineQueue to clear any raw m_OwningRegistry pointers to this
			// Region before m_AllocationRegistry destruction (flushes other regions early, trading
			// UAF window for pointer safety).
			Runtime::quarantine().flushEligible(SIZE_MAX, true);
			KERBECS_ASSERT(m_AllocationRegistry.liveCount() == 0 && "Region destroyed with live allocations still outstanding");
			m_AllocationRegistry.shutdown();
		}

		Region(const Region&) = delete;
		Region& operator=(const Region&) = delete;
		Region(Region&&) = delete;
		Region& operator=(Region&&) = delete;

		KERBECS_NODISCARD_MSG("Cannot discard Region initialization state")
		bool initialized() const noexcept { return m_Initialized; }

		KERBECS_NODISCARD_MSG("Cannot discard Region logical size")
		size_t size() const noexcept { return m_Size; }

		KERBECS_NODISCARD_MSG("Cannot discard Region allocation registry")
		Tracing::AllocationRegistry& allocationRegistry() noexcept {
			return m_AllocationRegistry;
		}

		KERBECS_NODISCARD_MSG("Cannot discard Region allocation registry")
		const Tracing::AllocationRegistry& allocationRegistry() const noexcept {
			return m_AllocationRegistry;
		}

		template<typename T>
		ShadowedMemory<T> allocate(size_t v_Count = 1, size_t v_Align = alignof(T)) noexcept {
			if (!m_Initialized || !m_RegionBase || v_Count == 0) return {};
			if (v_Count > std::numeric_limits<size_t>::max() / sizeof(T)) { _reportViolation(ViolationKind::SizeOverflow, nullptr, nullptr, v_Count); return {}; }
			const size_t userSize = v_Count * sizeof(T);
			const size_t alignment = std::max(v_Align, alignof(T));
			const size_t blockSize = LayoutT::blockSize(userSize, alignment);
			if (blockSize < userSize) { _reportViolation(ViolationKind::SizeOverflow, nullptr, nullptr, userSize); return {}; }
			void* block = m_AllocatorSupport.allocate(blockSize, alignment);
			if (!block) return {};
			auto offsets = LayoutT::place(block, blockSize, userSize, alignment);
			void* payload = static_cast<std::byte*>(block) + offsets.m_UserDataOffset;
			if (!_contains(payload, userSize) || !_setShadow(payload, userSize, true)) {
				_reportViolation(ViolationKind::WildPointer, payload, block, blockSize);
				m_AllocatorSupport.deallocate(block, blockSize); return {};
			}
			if (!m_AllocationRegistry.insert(block, payload, blockSize, userSize, reinterpret_cast<uintptr_t>(&m_Allocator), Tracing::Internal::currentThreadID(), nullptr, v_Count)) {
				_reportViolation(ViolationKind::OverlapDetected, payload, block, blockSize);
				KERBECS_UNUSED(_setShadow(payload, userSize, false)); m_AllocatorSupport.deallocate(block, blockSize); return {};
			}
			auto* node = m_AllocationRegistry.find(block);
			auto pool = m_AllocationRegistry.poolSegment();
			const size_t slot = static_cast<size_t>(node - pool.m_Pool);
			auto* info = static_cast<Runtime::AccessInfo*>(m_MetadataMapBase) + slot;
			info->m_UserSize = userSize;
			const uint64_t generation = node->m_Generation.load(std::memory_order_acquire);
			info->m_Generation.store(generation, std::memory_order_release);
			auto* shadow = static_cast<uint8_t*>(m_ShadowBlobPtr) + ((reinterpret_cast<uintptr_t>(payload) - reinterpret_cast<uintptr_t>(m_RegionBase)) >> Runtime::SHADOW_SCALE);
			return ShadowedMemory<T>(info, payload, shadow, generation);
		}

		template<typename T, typename... Args>
		bool construct(const ShadowedMemory<T>& v_Handle, Args&&... v_Args) noexcept {
			auto* node = _nodeFor(v_Handle);
			if (!node) { _reportViolation(ViolationKind::WildPointer, v_Handle.m_PayloadPtr, nullptr, sizeof(T)); return false; }
			if (reinterpret_cast<uintptr_t>(v_Handle.m_PayloadPtr) % alignof(T) != 0) {
				_reportViolation(ViolationKind::AlignmentViolation, v_Handle.m_PayloadPtr, node->m_BlockBase, sizeof(T));
				return false;
			}
			if (!_setShadow(v_Handle.m_PayloadPtr, sizeof(T), false)) return false;
			::new (v_Handle.m_PayloadPtr) T(std::forward<Args>(v_Args)...);
			return true;
		}

		template<typename T>
		bool destroy(const ShadowedMemory<T>& v_Handle) noexcept {
			auto* node = _nodeFor(v_Handle);
			if (!node) { _reportViolation(ViolationKind::DoubleFree, v_Handle.m_PayloadPtr, nullptr, sizeof(T)); return false; }
			auto* retiring = m_AllocationRegistry.beginRetiring(node->m_BlockBase, Tracing::Internal::currentThreadID(), ThreadPolicyT);
			if (!retiring) {
				// beginRetiring() folds three failures into one nullptr - re-read node
				// state to classify (best-effort, TOCTOU race against beginRetiring).
				ViolationKind kind = ViolationKind::DoubleFree;
				if constexpr (ThreadPolicyT == Shadow::Utils::ThreadPolicy::Strict) {
					if (Tracing::Internal::currentThreadID() != node->m_ThreadID) kind = ViolationKind::ThreadOwnership;
				}
				if (kind == ViolationKind::DoubleFree && node->m_State.load(std::memory_order_acquire) == Tracing::Internal::AllocationState::Retiring)
					kind = ViolationKind::RetiredBoundaryViolation;
				_reportViolation(kind, v_Handle.m_PayloadPtr, node->m_BlockBase, sizeof(T));
				return false;
			}
			const bool finalObject = retiring->m_LiveCount.fetch_sub(1, std::memory_order_acq_rel) == 1;
			// Invalidate generation before object teardown to prevent concurrent stale-handle reads in _check().
			if (finalObject) static_cast<Runtime::AccessInfo*>(v_Handle.m_MetaPtr)->m_Generation.store(0, std::memory_order_release);
			static_cast<T*>(v_Handle.m_PayloadPtr)->~T();
			std::memset(v_Handle.m_PayloadPtr, Runtime::TOMBSTONE, sizeof(T));
			KERBECS_UNUSED(_setShadow(v_Handle.m_PayloadPtr, sizeof(T), true));
			m_AllocationRegistry.endRetiring(node->m_BlockBase, Runtime::instance().m_Epoch.load(std::memory_order_acquire), &m_AllocatorSupport, &Shadow::Internal::MemorySupport<AllocatorT>::thunk);
			return true;
		}
	private:
		// Shared by every failure branch above instead of each duplicating the
		// stats-bump + makeViolation()/pushViolation() pair.
		void _reportViolation(ViolationKind v_Kind, void* p_Address, void* p_BlockBase, size_t v_BlockSize) noexcept {
			statsOnViolation(&Runtime::instance().m_Stats);
			Internal::pushViolation(makeViolation(v_Kind, p_Address, p_BlockBase, v_BlockSize));
		}

		template<typename T>
		Tracing::Internal::RegistryNode* _nodeFor(const ShadowedMemory<T>& v_Handle) noexcept {
			if (!v_Handle.m_MetaPtr || !m_MetadataMapBase) return nullptr;
			auto* info = static_cast<Runtime::AccessInfo*>(v_Handle.m_MetaPtr);
			const size_t slot = static_cast<size_t>(info - static_cast<Runtime::AccessInfo*>(m_MetadataMapBase));
			auto pool = m_AllocationRegistry.poolSegment();
			return slot < pool.m_Capacity ? pool.m_Pool + slot : nullptr;
		}
		bool _contains(const void* p_Address, size_t v_Size) const noexcept {
			if (!m_RegionBase || !p_Address || v_Size == 0) return false;
			const uintptr_t base = reinterpret_cast<uintptr_t>(m_RegionBase);
			const uintptr_t address = reinterpret_cast<uintptr_t>(p_Address);
			return address >= base && (address - base) <= m_Size && v_Size <= m_Size - (address - base);
		}

		bool _setShadow(void* p_Address, size_t v_Size, bool v_Poisoned) noexcept {
			if (!_contains(p_Address, v_Size) || !m_ShadowBlobPtr) return false;
			const uintptr_t base = reinterpret_cast<uintptr_t>(m_RegionBase);
			uintptr_t address = reinterpret_cast<uintptr_t>(p_Address);
			size_t remaining = v_Size;
			auto* shadowBase = static_cast<uint8_t*>(m_ShadowBlobPtr);
			while (remaining > 0) {
				const size_t userOffset = static_cast<size_t>(address - base);
				auto* shadowByte = shadowBase + (userOffset >> Runtime::SHADOW_SCALE);
				const size_t bitOffset = userOffset & ((size_t{ 1 } << Runtime::SHADOW_SCALE) - 1);
				const size_t span = std::min(remaining, (size_t{ 1 } << Runtime::SHADOW_SCALE) - bitOffset);
				if (v_Poisoned && !Memory::commitPageIfNeeded(shadowByte)) return false;
				if (!v_Poisoned && Memory::queryPage(shadowByte) != Memory::PageState::Committed) { address += span; remaining -= span; continue; }
				for (size_t i = 0; i < span; ++i) {
					const uint8_t mask = static_cast<uint8_t>(1u << (bitOffset + i));
					if (v_Poisoned) *shadowByte |= mask;
					else *shadowByte &= static_cast<uint8_t>(~mask);
				}
				address += span;
				remaining -= span;
			}
			return true;
		}

		AllocatorT& m_Allocator;
		size_t m_Size = 0;
		void* m_RegionBase = nullptr;
		void* m_ShadowBlobPtr = nullptr;
		void* m_MetadataMapBase = nullptr;
		Shadow::Internal::MemorySupport<AllocatorT> m_AllocatorSupport;
		Tracing::AllocationRegistry m_AllocationRegistry;
		bool m_Initialized = false;
	};

	// Convenience aliases - fix Layout + ThreadPolicy, leave only the Allocator
	// to name. Flexible is the common case (cross-thread destroy allowed via
	// the dtor lock), so it gets the plain name; Strict is the same Layout
	// with same-thread-only destroy enforced.
	template<typename AllocatorT>
	using NormalRegion = Region<Layout::NormalLayout, Shadow::Utils::ThreadPolicy::Flexible, AllocatorT>;
	template<typename AllocatorT>
	using NormalRegionStrict = Region<Layout::NormalLayout, Shadow::Utils::ThreadPolicy::Strict, AllocatorT>;

	template<typename AllocatorT>
	using EnhancedRegion = Region<Layout::EnhancedLayout, Shadow::Utils::ThreadPolicy::Flexible, AllocatorT>;
	template<typename AllocatorT>
	using EnhancedRegionStrict = Region<Layout::EnhancedLayout, Shadow::Utils::ThreadPolicy::Strict, AllocatorT>;

	template<typename AllocatorT>
	using StaticRegion = Region<Layout::StaticLayout, Shadow::Utils::ThreadPolicy::Flexible, AllocatorT>;
	template<typename AllocatorT>
	using StaticRegionStrict = Region<Layout::StaticLayout, Shadow::Utils::ThreadPolicy::Strict, AllocatorT>;

} // namespace Kerbecs
