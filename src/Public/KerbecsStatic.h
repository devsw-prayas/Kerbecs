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
#include "KerbecsAllocators.h"
#include "KerbecsRuntime.h"
#include "MemoryLayouts.h"
#include "Region.h"
#include "ShadowedMemory.h"

namespace Kerbecs::StaticSupport {

	using PersistentRegionT = StaticRegion<Allocators::StaticAllocator>;
	using GlobalRegionT = StaticRegion<Allocators::GlobalAllocator>;

	KERBECS_RUNTIME_API
		KERBECS_NODISCARD_MSG("Cannot discard persistent static region reference")
		PersistentRegionT& persistentRegion() noexcept;

	KERBECS_RUNTIME_API
		KERBECS_NODISCARD_MSG("Cannot discard global static region reference")
		GlobalRegionT& globalRegion() noexcept;

	template<typename T, auto RegionFn>
	struct KerbecsDestructor final {
		ShadowedMemory<T>* m_Handle = nullptr;

		explicit KerbecsDestructor(ShadowedMemory<T>* p_Handle) noexcept
			: m_Handle(p_Handle) {
		}

		KerbecsDestructor(const KerbecsDestructor&) = delete;
		KerbecsDestructor& operator=(const KerbecsDestructor&) = delete;
		KerbecsDestructor(KerbecsDestructor&&) = delete;
		KerbecsDestructor& operator=(KerbecsDestructor&&) = delete;

		~KerbecsDestructor() {
			if (!m_Handle || !static_cast<T*>(*m_Handle)) return;
			KERBECS_UNUSED(RegionFn().destroy(*m_Handle));
		}
	};

}

// __COUNTER__ needs one macro layer to expand before ## pasting.
#define KERBECS_CONCAT_IMPL(a, b) a##b
#define KERBECS_CONCAT(a, b) KERBECS_CONCAT_IMPL(a, b)

#define KERBECS_STATIC_INIT_IMPL(Type, name, region, counter, ...)                  \
    struct KERBECS_CONCAT(_KerbecsStaticInit_, counter) {                           \
        KERBECS_CONCAT(_KerbecsStaticInit_, counter)() {                            \
            name = region().allocate<Type>();                                       \
            KERBECS_ASSERT(static_cast<Type*>(name) && "Kerbecs static region exhausted"); \
            [[maybe_unused]] const bool ok = region().construct(name, ##__VA_ARGS__); \
            KERBECS_ASSERT(ok && "Kerbecs static construct failed");                \
        }                                                                            \
    };                                                                               \
    static KERBECS_CONCAT(_KerbecsStaticInit_, counter) KERBECS_CONCAT(_kerbecsStaticInitInst_, counter); \
    static ::Kerbecs::StaticSupport::KerbecsDestructor<Type, region>                \
        KERBECS_CONCAT(_kerbecsStaticDestructInst_, counter)(&name)

#define KERBECS_PERSISTENT(Type, name, ...)                                         \
    ::Kerbecs::ShadowedMemory<Type> name;                                           \
    KERBECS_STATIC_INIT_IMPL(Type, name, ::Kerbecs::StaticSupport::persistentRegion, __COUNTER__, ##__VA_ARGS__)

#define KERBECS_PERSISTENT_DECL(Type, name)                                         \
    extern ::Kerbecs::ShadowedMemory<Type> name

#define KERBECS_GLOBAL(Type, name, ...)                                             \
    static ::Kerbecs::ShadowedMemory<Type> name;                                    \
    KERBECS_STATIC_INIT_IMPL(Type, name, ::Kerbecs::StaticSupport::globalRegion, __COUNTER__, ##__VA_ARGS__)
