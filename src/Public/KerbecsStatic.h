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
#include "Shadow.h"
#include "MemoryZone.h"

namespace Kerbecs {
	template<typename T, typename SM, typename LG>
	struct KERBECS_RUNTIME_API KerbecsDestructor {
		Shadow::Shadow<Layout::StaticLayout, SM, LG>* m_Handle = nullptr;

		explicit KerbecsDestructor(
			Shadow::Shadow<Layout::StaticLayout, SM, LG>* p_Handle) noexcept
			: m_Handle(p_Handle) {
		}

		KerbecsDestructor(const KerbecsDestructor&) = delete;
		KerbecsDestructor& operator=(const KerbecsDestructor&) = delete;
		KerbecsDestructor(KerbecsDestructor&&) = delete;
		KerbecsDestructor& operator=(KerbecsDestructor&&) = delete;

		~KerbecsDestructor() {
			if (!m_Handle || !m_Handle->m_RawPtr) return;
			Shadow::shadowDestroy<T>(m_Handle);
		}
	};
}

#ifndef KERBECS_SHADOW_MAP_TYPE
#error "KERBECS_SHADOW_MAP_TYPE must be defined before including KerbecsStatics.h"
#endif

#ifndef  KERBECS_LOGGER_TYPE
#error "KERBECS_LOGGER_TYPE must be defined before including KerbecsStatics.h"
#endif

#ifndef KERBECS_HASH_TYPE
#error "KERBECS_HASH_TYPE must be defined before including KerbecsStatics.h"
#endif

#define KERBECS_SHADOW_HANDLE_TYPE(Type)            \
    ::Kerbecs::Shadow::Shadow<                      \
        ::Kerbecs::Layout::StaticLayout,            \
        KERBECS_SHADOW_MAP_TYPE,                    \
        KERBECS_LOGGER_TYPE,                        \
		KERBECS_HASH_TYPE>                          \

#define KERBECS_STATIC_INIT_IMPL(Type, name, tag, counter, ...)                     \
    struct _KerbecsInit_##counter {                                                  \
        _KerbecsInit_##counter() {                                                   \
            if (!::Kerbecs::MemoryZone::instance().m_Initialized)                   \
                ::Kerbecs::MemoryZone::initShadowzone();                             \
                                                                                     \
            constexpr size_t blockSz =                                               \
                ::Kerbecs::Layout::StaticLayout::blockSize(                          \
                    sizeof(Type), alignof(Type));                                    \
                                                                                     \
            void* block =                                                            \
                ::Kerbecs::MemoryZone::instance()                                    \
                    .m_StaticRegion.allocate(blockSz, alignof(Type));                \
            KERBECS_ASSERT(block && "Static region exhausted");                      \
                                                                                     \
            name.m_Map    = nullptr;                                                 \
            name.m_Logger = nullptr;                                                 \
            name.m_Name   = tag;                                                     \
                                                                                     \
            bool ok = ::Kerbecs::Shadow::shadowInit<Type>(                           \
                &name, block, blockSz, 1);                                           \
            KERBECS_ASSERT(ok && "shadowInit failed for static allocation");         \
                                                                                     \
            ok = ::Kerbecs::Shadow::shadowConstruct<Type>(&name, ##__VA_ARGS__);     \
            KERBECS_ASSERT(ok && "shadowConstruct failed for static allocation");    \
                                                                                     \
            ::Kerbecs::statsOnInit(                                                  \
                &::Kerbecs::MemoryZone::instance().m_Stats, blockSz);               \
        }                                                                            \
    };                                                                               \
    static _KerbecsInit_##counter        _kerbecsInitInst_##counter;                \
    static ::Kerbecs::KerbecsDestructor<                                             \
        Type,                                                                        \
        KERBECS_SHADOW_MAP_TYPE,                                                     \
        KERBECS_LOGGER_TYPE>             _kerbecsDestructor_##counter(&name)

#define KERBECS_PERSISTENT(Type, name, tag, ...)                \
    KERBECS_SHADOW_HANDLE_TYPE(Type) name;                      \
    KERBECS_STATIC_INIT_IMPL(Type, name, tag, __COUNTER__, ##__VA_ARGS__)

#define KERBECS_PERSISTENT_DECL(Type, name)                     \
    extern KERBECS_SHADOW_HANDLE_TYPE(Type) name

#define KERBECS_GLOBAL(Type, name, tag, ...)                    \
    static KERBECS_SHADOW_HANDLE_TYPE(Type) name;               \
    KERBECS_STATIC_INIT_IMPL(Type, name, tag, __COUNTER__, ##__VA_ARGS__)