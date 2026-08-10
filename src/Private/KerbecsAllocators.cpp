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

#include "Kerbecs.h"
#include "KerbecsAllocators.h"
#include "KerbecsDiagnostics.h"
#include "KerbecsMemory.h"

namespace Kerbecs::Allocators {

	void BumpAllocatorBase::init(void* p_Base, size_t v_Size) noexcept {
		m_Base = static_cast<uint8_t*>(p_Base);
		m_Size = v_Size;
		m_Bump.store(0, std::memory_order_relaxed);
	}

	void* BumpAllocatorBase::allocate(size_t v_Bytes, size_t v_Align) noexcept {
		uint8_t* ptr = _bumpReserve(v_Bytes, v_Align);
		if (!ptr) return nullptr;

		// Racing commits are safe — commitPageIfNeeded is idempotent.
		uintptr_t firstPage = reinterpret_cast<uintptr_t>(ptr)
			& ~static_cast<uintptr_t>(Memory::PAGE_SIZE - 1);
		uintptr_t lastPage = reinterpret_cast<uintptr_t>(ptr + v_Bytes - 1)
			& ~static_cast<uintptr_t>(Memory::PAGE_SIZE - 1);

		for (uintptr_t page = firstPage; page <= lastPage; page += Memory::PAGE_SIZE)
			KERBECS_UNUSED(Memory::commitPageIfNeeded(reinterpret_cast<void*>(page)));

		return ptr;
	}

	void BumpAllocatorBase::deallocate(void* /*p_Block*/, size_t /*v_Bytes*/) noexcept {}

	uint8_t* BumpAllocatorBase::_bumpReserve(size_t v_Bytes, size_t v_Align) noexcept {
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
				return m_Base + aligned;
			}
		}
	}

	void* ShadowzoneAllocator::allocate(size_t v_Bytes, size_t v_Align) noexcept {
		return _bumpReserve(v_Bytes, v_Align);
	}

	void ShadowzoneAllocator::deallocate(void* p_Block, size_t v_Bytes) noexcept {
		BumpAllocatorBase::deallocate(p_Block, v_Bytes);
	}

	void* StaticAllocator::allocate(size_t v_Bytes, size_t v_Align) noexcept {
		return BumpAllocatorBase::allocate(v_Bytes, v_Align);
	}

	void StaticAllocator::deallocate(void* p_Block, size_t v_Bytes) noexcept {
		BumpAllocatorBase::deallocate(p_Block, v_Bytes);
	}

	void* GlobalAllocator::allocate(size_t v_Bytes, size_t v_Align) noexcept {
		return BumpAllocatorBase::allocate(v_Bytes, v_Align);
	}

	void GlobalAllocator::deallocate(void* p_Block, size_t v_Bytes) noexcept {
		BumpAllocatorBase::deallocate(p_Block, v_Bytes);
	}

	void* MetadataZoneAllocator::allocate(size_t v_Bytes, size_t v_Align) noexcept {
		return BumpAllocatorBase::allocate(v_Bytes, v_Align);
	}

	void MetadataZoneAllocator::deallocate(void* p_Block, size_t v_Bytes) noexcept {
		BumpAllocatorBase::deallocate(p_Block, v_Bytes);
	}

} // namespace Kerbecs::Allocators
