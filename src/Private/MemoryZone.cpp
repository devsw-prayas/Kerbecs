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
#include "KerbecsMemory.h"
#include "MemoryZone.h"
#include "KerbecsDiagnostics.h"

namespace Kerbecs::MemoryZone {

    KerbecsMemoryZone& instance() noexcept {
        static KerbecsMemoryZone* s_Instance = new KerbecsMemoryZone();
        return *s_Instance;
    }

    KerbecsStats& stats() noexcept {
        return instance().m_Stats;
    }

    Tracing::AllocationRegistry& registry() noexcept {
        return instance().m_Registry;
    }

    Quarantine::QuarantineQueue& quarantine() noexcept {
        return instance().m_Quarantine;
    }

    bool initShadowzone() noexcept {
        return instance().init();
    }

    bool teardownShadowzone() noexcept {
        auto& zone = instance();

        if (zone.m_Shutdown.load(std::memory_order_acquire))
            return false;

        zone.m_Quarantine.flushEligible(
            zone.m_Registry.poolSegment(),
            SIZE_MAX);

        zone.m_Quarantine.shutdown();

        {
            const Tracing::NodePoolSegment seg = zone.m_Registry.poolSegment();
            bool leakFound = false;

            if (seg.m_Pool) {
                for (size_t i = 0; i < seg.m_Capacity; ++i) {
                    const auto& node = seg.m_Pool[i];
                    const auto state = node.m_State.load(std::memory_order_acquire);

                    if (state == Tracing::Internal::AllocationState::Live ||
                        state == Tracing::Internal::AllocationState::Retiring ||
                        state == Tracing::Internal::AllocationState::Quarantine) {
                        statsOnViolation(&zone.m_Stats);
                        leakFound = true;
                    }
                }
            }

            if (leakFound)
                KERBECS_TRAP();
        }

        zone.m_Registry.shutdown();

        constexpr size_t totalBytes =
            (static_cast<size_t>(SHADOWZONE_SIZE) +
             static_cast<size_t>(GLOBALZONE_SIZE) +
             static_cast<size_t>(STATICZONE_SIZE)) * Memory::GIBI_BYTE;

        KERBECS_UNUSED(Memory::release(zone.m_MemoryZone, totalBytes));

        zone.m_MemoryZone = nullptr;
        zone.m_ShadowZone = nullptr;
        zone.m_GlobalZone = nullptr;
        zone.m_StaticZone = nullptr;

        zone.m_Initialized.store(false, std::memory_order_release);
        zone.m_Shutdown.store(true, std::memory_order_release);

        return true;
    }

    bool KerbecsMemoryZone::init() noexcept {
        static std::mutex s_InitMutex;
        std::lock_guard<std::mutex> lock(s_InitMutex);

        if (m_Initialized.load(std::memory_order_acquire))
            return true;

        constexpr size_t shadowBytes =
            static_cast<size_t>(SHADOWZONE_SIZE) * Memory::GIBI_BYTE;

        constexpr size_t globalBytes =
            static_cast<size_t>(GLOBALZONE_SIZE) * Memory::GIBI_BYTE;

        constexpr size_t staticBytes =
            static_cast<size_t>(STATICZONE_SIZE) * Memory::GIBI_BYTE;

        constexpr size_t totalBytes =
            shadowBytes + globalBytes + staticBytes;

        // Reserve entire VA block in one call - no commit.
        m_MemoryZone = Memory::reserveAt(
            std::bit_cast<void*>(MEMORY_ZONE_ADDRESS),
            totalBytes);

        if (!m_MemoryZone)
            return false;

        auto* base = static_cast<std::byte*>(m_MemoryZone);

        m_ShadowZone = base;
        m_GlobalZone = base + shadowBytes;
        m_StaticZone = base + shadowBytes + globalBytes;

        // ----------------------------------------------------------------
        // Initialise the three lazy-commit bump allocators.
        // No commit happens here - pages are committed on first touch by
        // BumpAllocatorBase::allocate -> commitPageIfNeeded.
        // ----------------------------------------------------------------

        m_ShadowzoneAllocatorImpl.init(m_ShadowZone, shadowBytes);
        m_GlobalAllocatorImpl.init(m_GlobalZone, globalBytes);
        m_StaticAllocatorImpl.init(m_StaticZone, staticBytes);

        // Point the MemorySupport wrappers at the concrete allocator members.
        m_ShadowzoneAllocator = Shadow::Internal::MemorySupport<Allocators::ShadowzoneAllocator>{ &m_ShadowzoneAllocatorImpl };
        m_StaticAllocator = Shadow::Internal::MemorySupport<Allocators::StaticAllocator>{ &m_StaticAllocatorImpl };
        m_GlobalAllocator = Shadow::Internal::MemorySupport<Allocators::GlobalAllocator>{ &m_GlobalAllocatorImpl };

        // ----------------------------------------------------------------
        // Initialise registry (self-allocates node pool via Memory::allocate).
        // ----------------------------------------------------------------

        if (!m_Registry.init())
            goto fail;

        if (!m_Quarantine.init(QUARANTINE_CAPACITY, &m_Stats))
            goto fail;

        // Publish fully initialised state.
        m_Shutdown.store(false, std::memory_order_relaxed);
        m_Initialized.store(true, std::memory_order_release);

        return true;

    fail:
        // Best-effort cleanup. Registry and quarantine clean up their own
        // allocations in their respective shutdown paths.
        m_Registry.shutdown();
        m_Quarantine.shutdown();

        KERBECS_UNUSED(Memory::release(m_MemoryZone, totalBytes));

        m_MemoryZone = nullptr;
        m_ShadowZone = nullptr;
        m_GlobalZone = nullptr;
        m_StaticZone = nullptr;

        m_Shutdown.store(false, std::memory_order_relaxed);
        m_Initialized.store(false, std::memory_order_release);

        return false;
    }

    void* mapToShadow(void* p_User, size_t v_Size) noexcept {
        if (!p_User || v_Size == 0)
            return nullptr;

        auto& zone = instance();

        if (!zone.m_Initialized.load(std::memory_order_acquire) ||
            !zone.m_ShadowZone)
            return nullptr;

        uintptr_t userStart = reinterpret_cast<uintptr_t>(p_User);
        uintptr_t userEnd = userStart + v_Size - 1;

        uintptr_t shadowBase = reinterpret_cast<uintptr_t>(zone.m_ShadowZone);
        uintptr_t shadowZoneEnd = reinterpret_cast<uintptr_t>(zone.m_GlobalZone);

        uintptr_t shadowStart = (userStart >> SHADOW_SCALE) + shadowBase;
        uintptr_t shadowEnd = (userEnd >> SHADOW_SCALE) + shadowBase;

        if (shadowStart < shadowBase || shadowStart >= shadowZoneEnd)
            return nullptr;

        if (shadowEnd < shadowBase || shadowEnd >= shadowZoneEnd)
            return nullptr;

        return reinterpret_cast<void*>(shadowStart);
    }

    UserRange mapToUser(void* p_Shadow) noexcept {
        if (!p_Shadow)
            return { nullptr, nullptr };

        auto& zone = instance();

        if (!zone.m_Initialized.load(std::memory_order_acquire) ||
            !zone.m_ShadowZone)
            return { nullptr, nullptr };

        uintptr_t shadowAddr = reinterpret_cast<uintptr_t>(p_Shadow);
        uintptr_t shadowBase = reinterpret_cast<uintptr_t>(zone.m_ShadowZone);

        uintptr_t shadowZoneEnd =
            shadowBase +
            static_cast<size_t>(SHADOWZONE_SIZE) * Memory::GIBI_BYTE;

        if (shadowAddr < shadowBase || shadowAddr >= shadowZoneEnd)
            return { nullptr, nullptr };

        uintptr_t userBase = (shadowAddr - shadowBase) << SHADOW_SCALE;
        uintptr_t userEnd = userBase + ((1ULL << SHADOW_SCALE) - 1);

        return {
            reinterpret_cast<void*>(userBase),
            reinterpret_cast<void*>(userEnd)
        };
    }

    bool shadowPoison(void* p_UserPtr, size_t v_Size) noexcept {
        if (!p_UserPtr || v_Size == 0)
            return false;

        uint8_t* shadow =
            static_cast<uint8_t*>(mapToShadow(p_UserPtr, v_Size));

        if (!shadow)
            return false;

        uintptr_t addr = reinterpret_cast<uintptr_t>(p_UserPtr);
        size_t    remaining = v_Size;

        size_t bitOffset = addr & 0x7;
        size_t firstSpan = std::min<size_t>(remaining, 8 - bitOffset);

        if (!Memory::commitPageIfNeeded(shadow))
            return false;

        for (size_t i = 0; i < firstSpan; ++i)
            shadow[0] |= static_cast<uint8_t>(1u << (bitOffset + i));

        remaining -= firstSpan;
        KERBECS_UNUSED(addr += firstSpan);
        shadow += (bitOffset + firstSpan) >> 3;

        size_t fullBytes = remaining >> 3;

        for (size_t i = 0; i < fullBytes; ++i) {
            if ((reinterpret_cast<uintptr_t>(&shadow[i]) &
                 (Memory::PAGE_SIZE - 1)) == 0) {
                KERBECS_UNUSED(Memory::commitPageIfNeeded(&shadow[i]));
            }
            shadow[i] = 0xFF;
        }

        size_t tail = remaining & 0x7;

        if (tail > 0) {
            if ((reinterpret_cast<uintptr_t>(&shadow[fullBytes]) &
                 (Memory::PAGE_SIZE - 1)) == 0) {
                KERBECS_UNUSED(Memory::commitPageIfNeeded(&shadow[fullBytes]));
            }
            for (size_t i = 0; i < tail; ++i)
                shadow[fullBytes] |= static_cast<uint8_t>(1u << i);
        }

        return true;
    }

    bool shadowUnpoison(void* p_UserPtr, size_t v_Size) noexcept {
        if (!p_UserPtr || v_Size == 0)
            return false;

        uint8_t* shadow =
            static_cast<uint8_t*>(mapToShadow(p_UserPtr, v_Size));

        if (!shadow)
            return false;

        if (Memory::queryPage(shadow) != Memory::PageState::Committed)
            return true;

        uintptr_t addr = reinterpret_cast<uintptr_t>(p_UserPtr);
        size_t    remaining = v_Size;

        size_t bitOffset = addr & 0x7;
        size_t firstSpan = std::min<size_t>(remaining, 8 - bitOffset);

        for (size_t i = 0; i < firstSpan; ++i)
            shadow[0] &= ~static_cast<uint8_t>(1u << (bitOffset + i));

        remaining -= firstSpan;
        KERBECS_UNUSED(addr += firstSpan);
        shadow += (bitOffset + firstSpan) >> 3;

        size_t fullBytes = remaining >> 3;

        for (size_t i = 0; i < fullBytes; ++i)
            shadow[i] = 0x00;

        size_t tail = remaining & 0x7;

        if (tail > 0) {
            for (size_t i = 0; i < tail; ++i)
                shadow[fullBytes] &= ~static_cast<uint8_t>(1u << i);
        }

        return true;
    }

}