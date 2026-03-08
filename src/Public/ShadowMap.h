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
#include "MemoryZone.h"
#include "KerbecsEnforcements.h"

namespace Kerbecs {

    struct KERBECS_RUNTIME_API KerbecsShadowMap {

        // Delegate to the zone free functions which implement the full             
        // bit-level write path with lazy page commit.

        void poison(void* p_Ptr, size_t v_Size) noexcept {
            MemoryZone::shadowPoison(p_Ptr, v_Size);
        }

        void unpoison(void* p_Ptr, size_t v_Size) noexcept {
            MemoryZone::shadowUnpoison(p_Ptr, v_Size);
        }

        size_t countPoisoned(void* p_Ptr, size_t v_Size) noexcept {
            if (!p_Ptr || v_Size == 0)
                return 0;

            auto& zone = MemoryZone::instance();
            if (!zone.m_Initialized.load(std::memory_order_acquire) ||
                !zone.m_ShadowZone)
                return 0;

            const uintptr_t shadowBase =
                reinterpret_cast<uintptr_t>(zone.m_ShadowZone);

            const uintptr_t userStart =
                reinterpret_cast<uintptr_t>(p_Ptr);

            size_t poisoned = 0;
            size_t remaining = v_Size;
            uintptr_t addr = userStart;

            // ---- first partial shadow byte (addr not 8-byte aligned) ----
            size_t bitOffset = addr & 0x7;
            if (bitOffset != 0) {
                size_t span = std::min<size_t>(remaining, 8 - bitOffset);
                const uint8_t* shadowByte =
                    reinterpret_cast<const uint8_t*>((addr >> 3) + shadowBase);

                if (Memory::queryPage(shadowByte) == Memory::PageState::Committed) {
                    for (size_t i = 0; i < span; ++i)
                        if ((*shadowByte >> (bitOffset + i)) & 1u)
                            ++poisoned;
                }

                addr += span;
                remaining -= span;
            }

            // ---- full shadow bytes (8 user bytes each) ------------------
            size_t fullBytes = remaining >> 3;
            const uint8_t* shadowPtr =
                reinterpret_cast<const uint8_t*>((addr >> 3) + shadowBase);

            for (size_t i = 0; i < fullBytes; ++i) {
                // Only check page commit at page boundaries to avoid a
                // queryPage call per byte. Pages are 4 KiB = 4096 shadow
                // bytes, each covering 8 * 4096 = 32 768 user bytes.
                if ((reinterpret_cast<uintptr_t>(&shadowPtr[i]) &
                    (Memory::PAGE_SIZE - 1)) == 0) {
                    if (Memory::queryPage(&shadowPtr[i]) !=
                        Memory::PageState::Committed) {
                        // Entire page is uncommitted -> all zeros -> skip.
                        size_t bytesUntilNextPage =
                            std::min<size_t>(fullBytes - i,
                                Memory::PAGE_SIZE);
                        i += bytesUntilNextPage - 1;
                        addr += bytesUntilNextPage * 8;
                        remaining -= bytesUntilNextPage * 8;
                        continue;
                    }
                }
                // popcount: count set bits = poisoned user bytes in this group.
                poisoned += static_cast<size_t>(
                    std::popcount(static_cast<uint8_t>(shadowPtr[i])));
            }

            addr += fullBytes * 8;
            remaining -= fullBytes * 8;

            // ---- trailing partial shadow byte ---------------------------
            if (remaining > 0) {
                const uint8_t* shadowByte =
                    reinterpret_cast<const uint8_t*>((addr >> 3) + shadowBase);

                if (Memory::queryPage(shadowByte) == Memory::PageState::Committed) {
                    for (size_t i = 0; i < remaining; ++i)
                        if ((*shadowByte >> i) & 1u)
                            ++poisoned;
                }
            }

            return poisoned;
        }

        // ---- toShadow --------------------------------------------------
        void* toShadow(void* p_Ptr, size_t v_Size) noexcept {
            return MemoryZone::mapToShadow(p_Ptr, v_Size);
        }
    };

    KERBECS_STATIC_ASSERT(Enforcement::ShadowMapConcept<KerbecsShadowMap>, "Invalid default shadow map implementation");

}