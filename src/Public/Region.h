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
#include "MemorySupport.h"
#include "RegionRecord.h"
#include "ShadowUtils.h"
#include "ShadowedMemory.h"
#include <utility>
// Region is Kerbecs's caller-facing instrumentation wrapper (v0.2 SS4).
// It never owns the virtual-address range supplied by Allocator; it only owns
// the bookkeeping that makes allocations within that range observable.
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
			// Allocation APIs are deliberately introduced in the next slice. At
			// this stage no external path can populate the registry, so teardown
			// cannot leave a quarantine entry pointing at this registry.
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
			if (!m_Initialized || !m_RegionBase || v_Count == 0 || v_Count > std::numeric_limits<size_t>::max() / sizeof(T)) return {};
			const size_t userSize = v_Count * sizeof(T);
			const size_t alignment = std::max(v_Align, alignof(T));
			const size_t blockSize = LayoutT::blockSize(userSize, alignment);
			if (blockSize < userSize) return {};
			void* block = m_AllocatorSupport.allocate(blockSize, alignment);
			if (!block) return {};
			auto offsets = LayoutT::place(block, blockSize, userSize, alignment);
			void* payload = static_cast<std::byte*>(block) + offsets.m_UserDataOffset;
			if (!_contains(payload, userSize) || !_setShadow(payload, userSize, true)) { m_AllocatorSupport.deallocate(block, blockSize); return {}; }
			if (!m_AllocationRegistry.insert(block, payload, blockSize, userSize, reinterpret_cast<uintptr_t>(&m_Allocator), Tracing::Internal::currentThreadID(), nullptr, {}, v_Count)) {
				KERBECS_UNUSED(_setShadow(payload, userSize, false)); m_AllocatorSupport.deallocate(block, blockSize); return {};
			}
			auto* node = m_AllocationRegistry.find(block);
			auto pool = m_AllocationRegistry.poolSegment();
			const size_t slot = static_cast<size_t>(node - pool.m_Pool);
			auto* info = static_cast<Runtime::AccessInfo*>(m_MetadataMapBase) + slot;
			info->m_UserSize = userSize;
			info->m_Generation = node->m_Generation.load(std::memory_order_acquire);
			auto* shadow = static_cast<uint8_t*>(m_ShadowBlobPtr) + ((reinterpret_cast<uintptr_t>(payload) - reinterpret_cast<uintptr_t>(m_RegionBase)) >> Runtime::SHADOW_SCALE);
			return ShadowedMemory<T>(info, payload, shadow, info->m_Generation);
		}

		template<typename T, typename... Args>
		bool construct(const ShadowedMemory<T>& v_Handle, Args&&... v_Args) noexcept {
			auto* node = _nodeFor(v_Handle);
			if (!node || reinterpret_cast<uintptr_t>(v_Handle.m_PayloadPtr) % alignof(T) != 0) return false;
			if (!_setShadow(v_Handle.m_PayloadPtr, sizeof(T), false)) return false;
			::new (v_Handle.m_PayloadPtr) T(std::forward<Args>(v_Args)...);
			return true;
		}

		template<typename T>
		bool destroy(const ShadowedMemory<T>& v_Handle) noexcept {
			auto* node = _nodeFor(v_Handle);
			if (!node) return false;
			auto* retiring = m_AllocationRegistry.beginRetiring(node->m_BlockBase, Tracing::Internal::currentThreadID(), ThreadPolicyT);
			if (!retiring) return false;
			static_cast<T*>(v_Handle.m_PayloadPtr)->~T();
			std::memset(v_Handle.m_PayloadPtr, Runtime::TOMBSTONE, sizeof(T));
			KERBECS_UNUSED(_setShadow(v_Handle.m_PayloadPtr, sizeof(T), true));
			const bool finalObject = retiring->m_LiveCount.fetch_sub(1, std::memory_order_acq_rel) == 1;
			if (finalObject) static_cast<Runtime::AccessInfo*>(v_Handle.m_MetaPtr)->m_Generation = 0;
			m_AllocationRegistry.endRetiring(node->m_BlockBase, Runtime::instance().m_Epoch.load(std::memory_order_acquire), &m_AllocatorSupport, &Shadow::Internal::MemorySupport<AllocatorT>::thunk);
			return true;
		}
	private:
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

} // namespace Kerbecs
