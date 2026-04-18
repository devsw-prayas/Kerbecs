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
#include "KerbecsMemory.h"
#include "MemoryZone.h"
#include "ShadowUtils.h"
#include "KerbecsEnforcements.h"


#include "KerbecsDiagnostics.h"

namespace Kerbecs::Layout {

	/*
	 * NormalLayout
	 * 
	 * [ Leading redzone  | REDZONE_SIZE bytes                      ]
	 * [ User payload     | payloadSize bytes, aligned to alignof(T)]
	 * [ Trailing redzone | REDZONE_SIZE bytes                      ]
	 * [ NormalMetaData   | sizeof(NormalMetaData), aligned         ]
	 */

	struct KERBECS_RUNTIME_API NormalLayout {

		struct KERBECS_RUNTIME_API alignas(32) Offsets {
			size_t m_RedzoneOffsetLeading = 0;
			size_t m_UserDataOffset = 0;
			size_t m_RedzoneOffsetTrailing = 0;
			size_t m_MetaDataOffset = 0;
		};

		KERBECS_NODISCARD_MSG("Cannot discard computed block size")
			static size_t blockSize(size_t v_PayloadSize, size_t v_Align) noexcept {

			size_t afterLeading = Memory::alignUp(MemoryZone::REDZONE_SIZE, v_Align);
			size_t afterPayload = afterLeading + v_PayloadSize + MemoryZone::REDZONE_SIZE;
			size_t afterTrailing = Memory::alignUp(afterPayload, alignof(MemoryZone::NormalMetaData));
			return afterTrailing + sizeof(MemoryZone::NormalMetaData);
		}

		static Offsets place(void* p_Block, size_t v_BlockSize, size_t v_PayloadSize, size_t v_Align) noexcept {
			KERBECS_ASSERT(p_Block);
			KERBECS_ASSERT(v_BlockSize >= blockSize(v_PayloadSize, v_Align));

			auto* base = static_cast<std::byte*>(p_Block);
			Offsets o{};
			KERBECS_UNUSED(o);
			o.m_RedzoneOffsetLeading = 0;
			o.m_UserDataOffset = Memory::alignUp(MemoryZone::REDZONE_SIZE, v_Align);
			std::memset(base, MemoryZone::REDZONE, o.m_UserDataOffset);

			o.m_RedzoneOffsetTrailing = o.m_UserDataOffset + v_PayloadSize;
			o.m_MetaDataOffset = Memory::alignUp(
				o.m_RedzoneOffsetTrailing + MemoryZone::REDZONE_SIZE,
				alignof(MemoryZone::NormalMetaData));

			std::memset(base + o.m_RedzoneOffsetTrailing, MemoryZone::REDZONE, o.m_MetaDataOffset - o.m_RedzoneOffsetTrailing);
			::new (base + o.m_MetaDataOffset) MemoryZone::NormalMetaData{};

			return o;
		}

		static bool verifyGuards(const void* p_Block, const Offsets& v_Offsets, size_t v_BlockSize) noexcept {
			if (!p_Block) return false;

			const auto* base = static_cast<const std::byte*>(p_Block);

			size_t leadingSize = v_Offsets.m_UserDataOffset - v_Offsets.m_RedzoneOffsetLeading;
			if (!Shadow::Utils::verifyRedzone(base + v_Offsets.m_RedzoneOffsetLeading, leadingSize))
				return false;

			size_t trailingSize = v_Offsets.m_MetaDataOffset - v_Offsets.m_RedzoneOffsetTrailing;
			if (!Shadow::Utils::verifyRedzone(base + v_Offsets.m_RedzoneOffsetTrailing, trailingSize))
				return false;

			return true;
		}
	};

	static_assert(Enforcement::LayoutPolicyConcept<NormalLayout>);


	/*
	 * EnhancedLayout
	 * 
	 * [ Leading redzone          | REDZONE_SIZE bytes                           ]
	 * [ Leading EnhancedMetaData | sizeof(EnhancedMetaData), aligned            ]
	 * [ Leading canary           | CANARY_SIZE bytes                            ]
	 * [ User payload             | payloadSize bytes, aligned to alignof(T)     ]
	 * [ Trailing canary          | CANARY_SIZE bytes                            ]
	 * [ Trailing EnhancedMetaData| sizeof(EnhancedMetaData), aligned            ]
	 * [ Trailing redzone         | REDZONE_SIZE bytes                           ]
	 */

	struct KERBECS_RUNTIME_API EnhancedLayout {

		struct KERBECS_RUNTIME_API alignas(64) Offsets {
			size_t m_RedzoneOffsetLeading = 0;
			size_t m_MetaDataOffsetLeading = 0;
			size_t m_CanaryOffsetLeading = 0;
			size_t m_UserDataOffset = 0;
			size_t m_CanaryOffsetTrailing = 0;
			size_t m_MetaDataOffsetTrailing = 0;
			size_t m_RedzoneOffsetTrailing = 0;
		};

		KERBECS_NODISCARD_MSG("Cannot discard computed block size")
			static size_t blockSize(size_t v_PayloadSize, size_t v_Align) noexcept {
			// leading redzone
			size_t cursor = MemoryZone::REDZONE_SIZE;
			// leading metadata (aligned)
			cursor = Memory::alignUp(cursor, alignof(MemoryZone::EnhancedMetaData));
			cursor += sizeof(MemoryZone::EnhancedMetaData);
			// leading canary
			cursor += MemoryZone::CANARY_SIZE;
			// user payload (aligned)
			cursor = Memory::alignUp(cursor, v_Align);
			cursor += v_PayloadSize;
			// trailing canary
			cursor += MemoryZone::CANARY_SIZE;
			// trailing metadata (aligned)
			cursor = Memory::alignUp(cursor, alignof(MemoryZone::EnhancedMetaData));
			cursor += sizeof(MemoryZone::EnhancedMetaData);
			// trailing redzone
			cursor += MemoryZone::REDZONE_SIZE;
			return cursor;
		}

		static Offsets place(void* p_Block, size_t v_BlockSize, size_t v_PayloadSize, size_t v_Align) noexcept {
			KERBECS_ASSERT(p_Block);
			KERBECS_ASSERT(v_BlockSize >= blockSize(v_PayloadSize, v_Align));

			auto* base = static_cast<std::byte*>(p_Block);
			Offsets o{};
			KERBECS_UNUSED(o);
			o.m_RedzoneOffsetLeading = 0;
			o.m_MetaDataOffsetLeading = Memory::alignUp(
				MemoryZone::REDZONE_SIZE,
				alignof(MemoryZone::EnhancedMetaData));
			std::memset(base, MemoryZone::REDZONE, o.m_MetaDataOffsetLeading);

			::new (base + o.m_MetaDataOffsetLeading) MemoryZone::EnhancedMetaData{};

			o.m_CanaryOffsetLeading = o.m_MetaDataOffsetLeading + sizeof(MemoryZone::EnhancedMetaData);

			o.m_UserDataOffset = Memory::alignUp(
				o.m_CanaryOffsetLeading + MemoryZone::CANARY_SIZE,
				v_Align);
			_stampCanary(base + o.m_CanaryOffsetLeading, o.m_UserDataOffset - o.m_CanaryOffsetLeading);

			o.m_CanaryOffsetTrailing = o.m_UserDataOffset + v_PayloadSize;

			o.m_MetaDataOffsetTrailing = Memory::alignUp(
				o.m_CanaryOffsetTrailing + MemoryZone::CANARY_SIZE,
				alignof(MemoryZone::EnhancedMetaData));
			_stampCanary(base + o.m_CanaryOffsetTrailing, o.m_MetaDataOffsetTrailing - o.m_CanaryOffsetTrailing);
			::new (base + o.m_MetaDataOffsetTrailing) MemoryZone::EnhancedMetaData{};

			o.m_RedzoneOffsetTrailing = o.m_MetaDataOffsetTrailing + sizeof(MemoryZone::EnhancedMetaData);
			const size_t totalSize = v_BlockSize;
			std::memset(base + o.m_RedzoneOffsetTrailing, MemoryZone::REDZONE, totalSize - o.m_RedzoneOffsetTrailing);

			return o;
		}

		static bool verifyGuards(const void* p_Block, const Offsets& v_Offsets, size_t v_BlockSize) noexcept {
			if (!p_Block) return false;

			const auto* base = static_cast<const std::byte*>(p_Block);

			size_t leadingRZSize = v_Offsets.m_MetaDataOffsetLeading - v_Offsets.m_RedzoneOffsetLeading;
			if (!Shadow::Utils::verifyRedzone(base + v_Offsets.m_RedzoneOffsetLeading, leadingRZSize))
				return false;

			size_t leadingCanarySize = v_Offsets.m_UserDataOffset - v_Offsets.m_CanaryOffsetLeading;
			if (!Shadow::Utils::verifyCanaries(base + v_Offsets.m_CanaryOffsetLeading, leadingCanarySize))
				return false;

			size_t trailingCanarySize = v_Offsets.m_MetaDataOffsetTrailing - v_Offsets.m_CanaryOffsetTrailing;
			if (!Shadow::Utils::verifyCanaries(base + v_Offsets.m_CanaryOffsetTrailing, trailingCanarySize))
				return false;

			size_t trailingRZSize = v_BlockSize - v_Offsets.m_RedzoneOffsetTrailing;
			if (!Shadow::Utils::verifyRedzone(base + v_Offsets.m_RedzoneOffsetTrailing, trailingRZSize))
				return false;

			return true;
		}

	private:
		static void _stampCanary(std::byte* p_Dst, size_t v_Length) noexcept {
			size_t fullWords = v_Length / sizeof(uint64_t);
			size_t tail = v_Length % sizeof(uint64_t);
			for (size_t i = 0; i < fullWords; i++)
				std::memcpy(p_Dst + i * sizeof(uint64_t), &MemoryZone::GUARD_CANARY, sizeof(uint64_t));
			if (tail > 0)
				std::memcpy(p_Dst + fullWords * sizeof(uint64_t), &MemoryZone::GUARD_CANARY, tail);
		}
	};

	static_assert(Enforcement::LayoutPolicyConcept<EnhancedLayout>);


	/*
	 * StaticLayout
	 * 
	 * [ Leading redzone  | REDZONE_SIZE bytes                      ]
	 * [ Leading canary   | CANARY_SIZE bytes                       ]
	 * [ User payload     | payloadSize bytes, aligned to alignof(T)]
	 * [ Trailing canary  | CANARY_SIZE bytes                       ]
	 * [ Trailing redzone | REDZONE_SIZE bytes                      ]
	 * 
	 * No in-block metadata; handle persists in static region.
	 */

	struct KERBECS_RUNTIME_API StaticLayout {

		struct KERBECS_RUNTIME_API alignas(32) Offsets {
			size_t m_RedzoneOffsetLeading = 0;
			size_t m_CanaryOffsetLeading = 0;
			size_t m_UserDataOffset = 0;
			size_t m_CanaryOffsetTrailing = 0;
			size_t m_RedzoneOffsetTrailing = 0;
		};

		KERBECS_NODISCARD_MSG("Cannot discard computed block size")
			static size_t blockSize(size_t v_PayloadSize, size_t v_Align) noexcept {
			size_t cursor = MemoryZone::REDZONE_SIZE;              // leading redzone
			cursor += MemoryZone::CANARY_SIZE;                     // leading canary
			cursor = Memory::alignUp(cursor, v_Align);            // align for payload
			cursor += v_PayloadSize;                               // payload
			cursor += MemoryZone::CANARY_SIZE;                     // trailing canary
			cursor += MemoryZone::REDZONE_SIZE;                    // trailing redzone
			return cursor;
		}

		static Offsets place(void* p_Block, size_t v_BlockSize, size_t v_PayloadSize, size_t v_Align) noexcept {
			KERBECS_ASSERT(p_Block);
			KERBECS_ASSERT(v_BlockSize >= blockSize(v_PayloadSize, v_Align));

			auto* base = static_cast<std::byte*>(p_Block);
			Offsets o{};
			KERBECS_UNUSED(o);
			o.m_RedzoneOffsetLeading = 0;
			o.m_CanaryOffsetLeading = MemoryZone::REDZONE_SIZE;

			std::memset(base, MemoryZone::REDZONE, o.m_CanaryOffsetLeading);

			o.m_UserDataOffset = Memory::alignUp(
				o.m_CanaryOffsetLeading + MemoryZone::CANARY_SIZE,
				v_Align);
			_stampCanary(base + o.m_CanaryOffsetLeading, o.m_UserDataOffset - o.m_CanaryOffsetLeading);

			o.m_CanaryOffsetTrailing = o.m_UserDataOffset + v_PayloadSize;

			o.m_RedzoneOffsetTrailing = o.m_CanaryOffsetTrailing + MemoryZone::CANARY_SIZE;
			_stampCanary(base + o.m_CanaryOffsetTrailing, o.m_RedzoneOffsetTrailing - o.m_CanaryOffsetTrailing);
			const size_t totalSize = v_BlockSize;
			std::memset(base + o.m_RedzoneOffsetTrailing, MemoryZone::REDZONE, totalSize - o.m_RedzoneOffsetTrailing);

			return o;
		}

		static bool verifyGuards(const void* p_Block, const Offsets& v_Offsets, size_t v_BlockSize) noexcept {
			if (!p_Block) return false;

			const auto* base = static_cast<const std::byte*>(p_Block);

			size_t leadingRZSize = v_Offsets.m_CanaryOffsetLeading - v_Offsets.m_RedzoneOffsetLeading;
			if (!Shadow::Utils::verifyRedzone(base + v_Offsets.m_RedzoneOffsetLeading, leadingRZSize))
				return false;

			size_t leadingCanarySize = v_Offsets.m_UserDataOffset - v_Offsets.m_CanaryOffsetLeading;
			if (!Shadow::Utils::verifyCanaries(base + v_Offsets.m_CanaryOffsetLeading, leadingCanarySize))
				return false;

			size_t trailingCanarySize = v_Offsets.m_RedzoneOffsetTrailing - v_Offsets.m_CanaryOffsetTrailing;
			if (!Shadow::Utils::verifyCanaries(base + v_Offsets.m_CanaryOffsetTrailing, trailingCanarySize))
				return false;

			size_t trailingRZSize = v_BlockSize - v_Offsets.m_RedzoneOffsetTrailing;
			if (!Shadow::Utils::verifyRedzone(base + v_Offsets.m_RedzoneOffsetTrailing, trailingRZSize))
				return false;

			return true;
		}

	private:
		static void _stampCanary(std::byte* p_Dst, size_t v_Length) noexcept {
			size_t fullWords = v_Length / sizeof(uint64_t);
			size_t tail = v_Length % sizeof(uint64_t);
			for (size_t i = 0; i < fullWords; i++)
				std::memcpy(p_Dst + i * sizeof(uint64_t), &MemoryZone::GUARD_CANARY, sizeof(uint64_t));
			if (tail > 0)
				std::memcpy(p_Dst + fullWords * sizeof(uint64_t), &MemoryZone::GUARD_CANARY, tail);
		}
	};

	static_assert(Enforcement::LayoutPolicyConcept<StaticLayout>);

} 