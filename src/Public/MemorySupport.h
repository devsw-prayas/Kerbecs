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

namespace Kerbecs::Shadow::Internal {
	// Non-owning pointer wrapper around concrete allocator A (stores A* owned externally).
	// Provides static type-erased thunk(p_Alloc, p_Block, v_Bytes) stamped into QuarantineEntry,
	// allowing QuarantineQueue to flush deferred deallocations without knowing template parameter A.
	template<typename A>
		requires Enforcement::AllocatorConcept<A>
	struct KERBECS_RUNTIME_API MemorySupport final {
		using allocator_ = A;

		A* m_Allocator = nullptr;

		constexpr MemorySupport() noexcept = default;

		explicit constexpr MemorySupport(A* p_Allocator) noexcept
			: m_Allocator(p_Allocator) {
		}

		// Non-owning - copy and move just transfer the pointer.
		MemorySupport(const MemorySupport&) noexcept = default;
		MemorySupport& operator=(const MemorySupport&) noexcept = default;
		MemorySupport(MemorySupport&&) noexcept = default;
		MemorySupport& operator=(MemorySupport&&) noexcept = default;

		~MemorySupport() = default;

		KERBECS_NODISCARD_MSG("Cannot discard allocated block pointer")
			void* allocate(size_t v_Bytes, size_t v_Align) noexcept {
			return m_Allocator->allocate(v_Bytes, v_Align);
		}

		void deallocate(void* p_Block, size_t v_Bytes) noexcept {
			m_Allocator->deallocate(p_Block, v_Bytes);
		}

		static void thunk(void* p_Alloc, void* p_Block, size_t v_Bytes) noexcept {
			static_cast<MemorySupport<A>*>(p_Alloc)->deallocate(p_Block, v_Bytes);
		}
	};

}
