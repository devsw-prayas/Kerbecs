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

        // Ensure any nodes in the Retiring state have their dtors finished
        // before we audit the registry.
        zone.m_Epoch.fetch_add(4, std::memory_order_acq_rel);

        zone.m_Quarantine.flushEligible(
            zone.m_Registry.poolSegment(),
            SIZE_MAX,
            true);

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
            std::cout << "[KERBECS] SHUTDOWN REPORT\n";
            std::cout << "  Total Violations:   " << stats().m_TotalViolations << "\n";
            std::cout << "  Active Allocations: " << stats().m_ActiveAllocations << " (Leaks if > 0)\n";
            std::cout << "  Peak Usage (Bytes): " << stats().m_PeakUsage << "\n";

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

        m_ShadowzoneAllocatorImpl.init(m_ShadowZone, shadowBytes);
        m_GlobalAllocatorImpl.init(m_GlobalZone, globalBytes);
        m_StaticAllocatorImpl.init(m_StaticZone, staticBytes);

        // Point the MemorySupport wrappers at the concrete allocator members.
        m_ShadowzoneAllocator = Shadow::Internal::MemorySupport<Allocators::ShadowzoneAllocator>{ &m_ShadowzoneAllocatorImpl };
        m_StaticAllocator = Shadow::Internal::MemorySupport<Allocators::StaticAllocator>{ &m_StaticAllocatorImpl };
        m_GlobalAllocator = Shadow::Internal::MemorySupport<Allocators::GlobalAllocator>{ &m_GlobalAllocatorImpl };

        if (!m_Registry.init() || !m_Quarantine.init(QUARANTINE_CAPACITY, &m_Stats)) {
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

        m_Shutdown.store(false, std::memory_order_relaxed);
        m_Initialized.store(true, std::memory_order_release);
        return true;
    }

    void* mapToShadow(void* p_User, size_t v_Size) noexcept {
        if (!p_User || v_Size == 0)
            return nullptr;

        auto& zone = instance();

        if (!zone.m_Initialized.load(std::memory_order_acquire) ||
            !zone.m_ShadowZone || !zone.m_MemoryZone)
            return nullptr;

        const uintptr_t userStart = reinterpret_cast<uintptr_t>(p_User);
        const uintptr_t zoneBase = reinterpret_cast<uintptr_t>(zone.m_MemoryZone);

        if (userStart < zoneBase)
            return nullptr;

        const uintptr_t relativeOffset = userStart - zoneBase;
        const uintptr_t shadowBase = reinterpret_cast<uintptr_t>(zone.m_ShadowZone);
        const uintptr_t shadowZoneEnd = reinterpret_cast<uintptr_t>(zone.m_GlobalZone);

        const uintptr_t shadowStart = (relativeOffset >> SHADOW_SCALE) + shadowBase;

        if (shadowStart < shadowBase || shadowStart >= shadowZoneEnd)
            return nullptr;

        return reinterpret_cast<void*>(shadowStart);
    }

    UserRange mapToUser(void* p_Shadow) noexcept {
        if (!p_Shadow)
            return { nullptr, nullptr };

        auto& zone = instance();

        if (!zone.m_Initialized.load(std::memory_order_acquire) ||
            !zone.m_ShadowZone || !zone.m_MemoryZone)
            return { nullptr, nullptr };

        const uintptr_t shadowAddr = reinterpret_cast<uintptr_t>(p_Shadow);
        const uintptr_t shadowBase = reinterpret_cast<uintptr_t>(zone.m_ShadowZone);
        const uintptr_t shadowZoneEnd = reinterpret_cast<uintptr_t>(zone.m_GlobalZone);

        if (shadowAddr < shadowBase || shadowAddr >= shadowZoneEnd)
            return { nullptr, nullptr };

        const uintptr_t zoneBase = reinterpret_cast<uintptr_t>(zone.m_MemoryZone);
        const uintptr_t relativeOffset = (shadowAddr - shadowBase) << SHADOW_SCALE;
        const uintptr_t userBase = relativeOffset + zoneBase;
        const uintptr_t userEnd = userBase + ((1ULL << SHADOW_SCALE) - 1);

        return {
            reinterpret_cast<void*>(userBase),
            reinterpret_cast<void*>(userEnd)
        };
    }

    bool shadowPoison(void* p_UserPtr, size_t v_Size) noexcept {
        if (!p_UserPtr || v_Size == 0) return false;

        auto& zone = instance();
        const uintptr_t userStart = reinterpret_cast<uintptr_t>(p_UserPtr);
        const uintptr_t zoneBase = reinterpret_cast<uintptr_t>(zone.m_MemoryZone);
        const uintptr_t shadowBase = reinterpret_cast<uintptr_t>(zone.m_ShadowZone);

        uintptr_t addr = userStart;
        size_t remaining = v_Size;

        while (remaining > 0) {
            const uintptr_t rel = addr - zoneBase;
            const uintptr_t shadowByteAddr = (rel >> SHADOW_SCALE) + shadowBase;
            uint8_t* shadowByte = reinterpret_cast<uint8_t*>(shadowByteAddr);

            if (!Memory::commitPageIfNeeded(shadowByte)) return false;

            size_t bitOffset = addr & 0x7;
            size_t span = std::min<size_t>(remaining, 8 - bitOffset);

            for (size_t i = 0; i < span; ++i) {
                *shadowByte |= static_cast<uint8_t>(1u << (bitOffset + i));
            }

            addr += span;
            remaining -= span;
        }
        return true;
    }

    bool shadowUnpoison(void* p_UserPtr, size_t v_Size) noexcept {
        if (!p_UserPtr || v_Size == 0) return false;

        auto& zone = instance();
        const uintptr_t userStart = reinterpret_cast<uintptr_t>(p_UserPtr);
        const uintptr_t zoneBase = reinterpret_cast<uintptr_t>(zone.m_MemoryZone);
        const uintptr_t shadowBase = reinterpret_cast<uintptr_t>(zone.m_ShadowZone);

        uintptr_t addr = userStart;
        size_t remaining = v_Size;

        while (remaining > 0) {
            const uintptr_t rel = addr - zoneBase;
            const uintptr_t shadowByteAddr = (rel >> SHADOW_SCALE) + shadowBase;
            uint8_t* shadowByte = reinterpret_cast<uint8_t*>(shadowByteAddr);

            const size_t bitOffset = addr & 0x7;
            const size_t span = std::min<size_t>(remaining, 8 - bitOffset);

            // Uncommitted pages are implicitly zeroed/unpoisoned.
            if (Memory::queryPage(shadowByte) == Memory::PageState::Committed) {
                for (size_t i = 0; i < span; ++i)
                    *shadowByte &= ~static_cast<uint8_t>(1u << (bitOffset + i));
            }

            addr += span;
            remaining -= span;
        }
        return true;
    }

}