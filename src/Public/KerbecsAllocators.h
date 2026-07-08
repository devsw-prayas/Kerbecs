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
#include "KerbecsDiagnostics.h"
#include "KerbecsMemory.h"
#include "KerbecsEnforcements.h"

namespace Kerbecs::Allocators {
	struct KERBECS_RUNTIME_API BumpAllocatorBase {
		uint8_t* m_Base = nullptr;
		size_t              m_Size = 0;
		std::atomic<size_t> m_Bump{ 0 };

		// Non-copyable, non-movable - lives as a zone member.
		BumpAllocatorBase() = default;
		BumpAllocatorBase(const BumpAllocatorBase&) = delete;
		BumpAllocatorBase& operator=(const BumpAllocatorBase&) = delete;
		BumpAllocatorBase(BumpAllocatorBase&&) noexcept = delete;
		BumpAllocatorBase& operator=(BumpAllocatorBase&&) noexcept = delete;
		~BumpAllocatorBase() = default;

		void init(void* p_Base, size_t v_Size) noexcept {
			m_Base = static_cast<uint8_t*>(p_Base);
			m_Size = v_Size;
			m_Bump.store(0, std::memory_order_relaxed);
		}

		KERBECS_NODISCARD_MSG("Cannot discard allocated block pointer")
			void* allocate(size_t v_Bytes, size_t v_Align) noexcept {
			if (!m_Base || v_Bytes == 0 || v_Align == 0) return nullptr;

			KERBECS_ASSERT((v_Align & (v_Align - 1)) == 0);

			size_t current = m_Bump.load(std::memory_order_relaxed);

			for (;;) {
				size_t aligned = Memory::alignUp(current, v_Align);
				size_t next = aligned + v_Bytes;

				if (next > m_Size) return nullptr;

				if (m_Bump.compare_exchange_weak(
					current,
					next,
					std::memory_order_release,
					std::memory_order_relaxed)) {
					uint8_t* ptr = m_Base + aligned;

					// commitPageIfNeeded is idempotent on both platforms — racing commits are safe.
					uintptr_t firstPage = reinterpret_cast<uintptr_t>(ptr)
						& ~static_cast<uintptr_t>(Memory::PAGE_SIZE - 1);
					uintptr_t lastPage = reinterpret_cast<uintptr_t>(ptr + v_Bytes - 1)
						& ~static_cast<uintptr_t>(Memory::PAGE_SIZE - 1);

					for (uintptr_t page = firstPage; page <= lastPage; page += Memory::PAGE_SIZE)
						KERBECS_UNUSED(Memory::commitPageIfNeeded(reinterpret_cast<void*>(page)));

					return ptr;
				}
			}
		}

		void deallocate(void* /*p_Block*/, size_t /*v_Bytes*/) noexcept {}
	};

	struct KERBECS_RUNTIME_API ShadowzoneAllocator final : BumpAllocatorBase {
		KERBECS_NODISCARD_MSG("Cannot discard allocated shadow block pointer")
			void* allocate(size_t v_Bytes, size_t v_Align) noexcept {
			return BumpAllocatorBase::allocate(v_Bytes, v_Align);
		}

		void deallocate(void* p_Block, size_t v_Bytes) noexcept {
			BumpAllocatorBase::deallocate(p_Block, v_Bytes);
		}
	};

	struct KERBECS_RUNTIME_API StaticAllocator final : BumpAllocatorBase {
		KERBECS_NODISCARD_MSG("Cannot discard allocated static block pointer")
			void* allocate(size_t v_Bytes, size_t v_Align) noexcept {
			return BumpAllocatorBase::allocate(v_Bytes, v_Align);
		}

		void deallocate(void* p_Block, size_t v_Bytes) noexcept {
			BumpAllocatorBase::deallocate(p_Block, v_Bytes);
		}
	};

	struct KERBECS_RUNTIME_API GlobalAllocator final : BumpAllocatorBase {
		KERBECS_NODISCARD_MSG("Cannot discard allocated global block pointer")
			void* allocate(size_t v_Bytes, size_t v_Align) noexcept {
			return BumpAllocatorBase::allocate(v_Bytes, v_Align);
		}

		void deallocate(void* p_Block, size_t v_Bytes) noexcept {
			BumpAllocatorBase::deallocate(p_Block, v_Bytes);
		}
	};

	// MetadataZoneAllocator (v0.2 SS4.1 / SS8)
	//
	// Backs Region::m_MetadataMapBase. Per-allocation metadata/guard regions
	// stamped here get their own poison bits (v0.2 SS8.1) - previously the
	// shadow bitmap only ever covered user payload, leaving metadata/guard
	// blocks invisible to wild-pointer checks.
	struct KERBECS_RUNTIME_API MetadataZoneAllocator final : BumpAllocatorBase {
		KERBECS_NODISCARD_MSG("Cannot discard allocated metadata block pointer")
			void* allocate(size_t v_Bytes, size_t v_Align) noexcept {
			return BumpAllocatorBase::allocate(v_Bytes, v_Align);
		}

		void deallocate(void* p_Block, size_t v_Bytes) noexcept {
			BumpAllocatorBase::deallocate(p_Block, v_Bytes);
		}
	};

	KERBECS_STATIC_ASSERT(Enforcement::AllocatorConcept<ShadowzoneAllocator>, "Concept not satisfied");
	KERBECS_STATIC_ASSERT(Enforcement::AllocatorConcept<StaticAllocator>, "Concept not satisfied");
	KERBECS_STATIC_ASSERT(Enforcement::AllocatorConcept<GlobalAllocator>, "Concept not satisfied");
	KERBECS_STATIC_ASSERT(Enforcement::AllocatorConcept<MetadataZoneAllocator>, "Concept not satisfied");
}
