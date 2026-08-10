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

		void init(void* p_Base, size_t v_Size) noexcept;

		KERBECS_NODISCARD_MSG("Cannot discard allocated block pointer")
			void* allocate(size_t v_Bytes, size_t v_Align) noexcept;

		void deallocate(void* /*p_Block*/, size_t /*v_Bytes*/) noexcept;

	protected:
		// Bumps VA cursor without page commits. Sparsely-touched callers (e.g.
		// ShadowzoneAllocator) rely on lazy commitPageIfNeeded in Region::_setShadow
		// rather than eager per-page loops that cause huge front VirtualAlloc commits.
		KERBECS_NODISCARD_MSG("Cannot discard reserved block pointer")
			uint8_t* _bumpReserve(size_t v_Bytes, size_t v_Align) noexcept;
	};

	struct KERBECS_RUNTIME_API ShadowzoneAllocator final : BumpAllocatorBase {
		// Deliberately skips BumpAllocatorBase::allocate's eager per-page commit -
		// this blob spans the whole zone but is only ever touched one shadow byte
		// at a time (Region::_setShadow), so eager-committing here is what caused
		// the 125GB-reservation bug this class was fixed for (see 3f0a41b).
		KERBECS_NODISCARD_MSG("Cannot discard allocated shadow block pointer")
			void* allocate(size_t v_Bytes, size_t v_Align) noexcept;

		void deallocate(void* p_Block, size_t v_Bytes) noexcept;
	};

	struct KERBECS_RUNTIME_API StaticAllocator final : BumpAllocatorBase {
		KERBECS_NODISCARD_MSG("Cannot discard allocated static block pointer")
			void* allocate(size_t v_Bytes, size_t v_Align) noexcept;

		void deallocate(void* p_Block, size_t v_Bytes) noexcept;
	};

	struct KERBECS_RUNTIME_API GlobalAllocator final : BumpAllocatorBase {
		KERBECS_NODISCARD_MSG("Cannot discard allocated global block pointer")
			void* allocate(size_t v_Bytes, size_t v_Align) noexcept;

		void deallocate(void* p_Block, size_t v_Bytes) noexcept;
	};

	// MetadataZoneAllocator: Backs Region::m_MetadataMapBase.
	// Metadata/guard regions stamped here get dedicated poison bits,
	// allowing wild-pointer checks to catch out-of-bounds hits into metadata.
	struct KERBECS_RUNTIME_API MetadataZoneAllocator final : BumpAllocatorBase {
		KERBECS_NODISCARD_MSG("Cannot discard allocated metadata block pointer")
			void* allocate(size_t v_Bytes, size_t v_Align) noexcept;

		void deallocate(void* p_Block, size_t v_Bytes) noexcept;
	};

	KERBECS_STATIC_ASSERT(Enforcement::AllocatorConcept<ShadowzoneAllocator>, "Concept not satisfied");
	KERBECS_STATIC_ASSERT(Enforcement::AllocatorConcept<StaticAllocator>, "Concept not satisfied");
	KERBECS_STATIC_ASSERT(Enforcement::AllocatorConcept<GlobalAllocator>, "Concept not satisfied");
	KERBECS_STATIC_ASSERT(Enforcement::AllocatorConcept<MetadataZoneAllocator>, "Concept not satisfied");
}
