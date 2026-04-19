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
                !zone.m_ShadowZone || !zone.m_MemoryZone)
                return 0;

            const uintptr_t userStart = reinterpret_cast<uintptr_t>(p_Ptr);
            const uintptr_t zoneBase = reinterpret_cast<uintptr_t>(zone.m_MemoryZone);

            // If the address is outside the tracked memory zone, it's effectively untracked.
            if (userStart < zoneBase)
                return v_Size;

            const uintptr_t relativeOffset = userStart - zoneBase;
            const uintptr_t shadowBase = reinterpret_cast<uintptr_t>(zone.m_ShadowZone);
            const uintptr_t shadowZoneEnd = reinterpret_cast<uintptr_t>(zone.m_GlobalZone);

            const uintptr_t shadowStart = (relativeOffset >> MemoryZone::SHADOW_SCALE) + shadowBase;

            const uintptr_t relativeEnd = (userStart + v_Size - 1) - zoneBase;
            const uintptr_t shadowLast = (relativeEnd >> MemoryZone::SHADOW_SCALE) + shadowBase;

            // Bounds check inside the shadow zone
            if (shadowStart < shadowBase || shadowStart >= shadowZoneEnd ||
                shadowLast < shadowBase || shadowLast >= shadowZoneEnd)
                return v_Size; // Assume poisoned if out of bounds

            size_t poisoned = 0;
            size_t remaining = v_Size;
            uintptr_t addr = userStart;

            while (remaining > 0) {
                const uintptr_t rel = addr - zoneBase;
                const uintptr_t shadowByteAddr = (rel >> MemoryZone::SHADOW_SCALE) + shadowBase;
                const uint8_t* shadowByte = reinterpret_cast<const uint8_t*>(shadowByteAddr);

                if (Memory::queryPage(shadowByte) == Memory::PageState::Committed) {
                    size_t bitOffset = addr & 0x7;
                    size_t span = std::min<size_t>(remaining, 8 - bitOffset);

                    if (bitOffset == 0 && span == 8) {
                        poisoned += std::popcount(*shadowByte);
                    } else {
                        for (size_t i = 0; i < span; ++i) {
                            if ((*shadowByte >> (bitOffset + i)) & 1u)
                                ++poisoned;
                        }
                    }
                }

                size_t bitOffset = addr & 0x7;
                size_t span = std::min<size_t>(remaining, 8 - bitOffset);
                addr += span;
                remaining -= span;
            }

            return poisoned;
        }

        void* toShadow(void* p_Ptr, size_t v_Size) noexcept {
            return MemoryZone::mapToShadow(p_Ptr, v_Size);
        }
    };

    KERBECS_STATIC_ASSERT(Enforcement::ShadowMapConcept<KerbecsShadowMap>, "Invalid default shadow map implementation");

}
