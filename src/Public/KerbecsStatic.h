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
#include "MemoryLayouts.h"
#include "ShadowPtr.h"
#include "MemoryZone.h"

namespace Kerbecs {

    template<typename T, typename LG, typename HA, typename AC, Shadow::Utils::ThreadPolicy TP = Shadow::Utils::ThreadPolicy::Flexible>
    struct KERBECS_RUNTIME_API KerbecsDestructor {
        Shadow::ShadowPtr<Layout::StaticLayout, LG, HA, AC, TP>* m_Handle = nullptr;

        explicit KerbecsDestructor(
            Shadow::ShadowPtr<Layout::StaticLayout, LG, HA, AC, TP>* p_Handle) noexcept
            : m_Handle(p_Handle) {
        }

        KerbecsDestructor(const KerbecsDestructor&) = delete;
        KerbecsDestructor& operator=(const KerbecsDestructor&) = delete;
        KerbecsDestructor(KerbecsDestructor&&) = delete;
        KerbecsDestructor& operator=(KerbecsDestructor&&) = delete;

        ~KerbecsDestructor() {
            if (!m_Handle || !m_Handle->m_RawPtr) return;
            Shadow::shadowDestroy<T, Layout::StaticLayout, LG, HA, AC, TP>(m_Handle);
        }
    };

}

#ifndef KERBECS_LOGGER_TYPE
#error "KERBECS_LOGGER_TYPE must be defined before including KerbecsStatic.h"
#endif

#ifndef KERBECS_HASH_TYPE
#error "KERBECS_HASH_TYPE must be defined before including KerbecsStatic.h"
#endif

#ifndef KERBECS_ALLOCATOR_TYPE
#error "KERBECS_ALLOCATOR_TYPE must be defined before including KerbecsStatic.h"
#endif

// Full Shadow handle type - four params (shadow map removed).
#define KERBECS_SHADOW_HANDLE_TYPE(Type)            \
    ::Kerbecs::Shadow::ShadowPtr<                   \
        ::Kerbecs::Layout::StaticLayout,            \
        KERBECS_LOGGER_TYPE,                        \
        KERBECS_HASH_TYPE,                          \
        KERBECS_ALLOCATOR_TYPE>                     \

// KERBECS_STATIC_INIT_IMPL
//
// Internal implementation macro shared by KERBECS_PERSISTENT and
// KERBECS_GLOBAL. AllocExpr is the expression that produces the block
// pointer - callers pass the appropriate zone allocator member.
#define KERBECS_STATIC_INIT_IMPL(Type, name, tag, allocMember, counter, ...)        \
    struct _KerbecsInit_##counter {                                                  \
        _KerbecsInit_##counter() {                                                   \
            if (!::Kerbecs::MemoryZone::instance().m_Initialized)                   \
                ::Kerbecs::MemoryZone::initShadowzone();                             \
            constexpr size_t blockSz =                                               \
                ::Kerbecs::Layout::StaticLayout::blockSize(                          \
                    sizeof(Type), alignof(Type));                                    \
            void* block =                                                            \
                ::Kerbecs::MemoryZone::instance()                                    \
                    .allocMember.allocate(blockSz, alignof(Type));                   \
            KERBECS_ASSERT(block && "Zone exhausted");                               \
            name.m_Logger        = nullptr;                                          \
            name.m_Name          = tag;                                              \
            name.m_UserAllocator =                                                   \
                &::Kerbecs::MemoryZone::instance().allocMember;                      \
            bool ok = ::Kerbecs::Shadow::shadowInit<Type>(                           \
                &name, block, blockSz, 1);                                           \
            KERBECS_ASSERT(ok && "shadowInit failed");                               \
            ok = ::Kerbecs::Shadow::shadowConstruct<Type>(&name, ##__VA_ARGS__);     \
            KERBECS_ASSERT(ok && "shadowConstruct failed");                          \
        }                                                                            \
    };                                                                               \
    static _KerbecsInit_##counter _kerbecsInitInst_##counter;                       \
    static ::Kerbecs::KerbecsDestructor<                                             \
        Type,                                                                        \
        KERBECS_LOGGER_TYPE,                                                         \
        KERBECS_HASH_TYPE,                                                           \
        KERBECS_ALLOCATOR_TYPE> _kerbecsDestructor_##counter(&name)

// KERBECS_PERSISTENT
//
// Allocates from m_StaticAllocator (StaticZone). Suitable for objects that
// must persist for the lifetime of the process.
#define KERBECS_PERSISTENT(Type, name, tag, ...)                    \
    KERBECS_SHADOW_HANDLE_TYPE(Type) name;                          \
    KERBECS_STATIC_INIT_IMPL(Type, name, tag, m_StaticAllocator,    \
        __COUNTER__, ##__VA_ARGS__)

#define KERBECS_PERSISTENT_DECL(Type, name)                         \
    extern KERBECS_SHADOW_HANDLE_TYPE(Type) name

// KERBECS_GLOBAL
//
// Allocates from m_GlobalAllocator (GlobalZone). Suitable for module-level
// singletons with controlled lifetime.
#define KERBECS_GLOBAL(Type, name, tag, ...)                        \
    static KERBECS_SHADOW_HANDLE_TYPE(Type) name;                   \
    KERBECS_STATIC_INIT_IMPL(Type, name, tag, m_GlobalAllocator,    \
        __COUNTER__, ##__VA_ARGS__)