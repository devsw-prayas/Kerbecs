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

// Static region support for KERBECS_PERSISTENT / KERBECS_GLOBAL macros.
// Vends process-wide Region handles backed by KerbecsRuntime's m_StaticAllocatorImpl and m_GlobalAllocatorImpl.
namespace Kerbecs::StaticSupport {

	// Flexible ThreadPolicy: Static objects are process-lifetime singletons constructed/destroyed across static init/deinit.
	using PersistentRegionT = StaticRegion<Allocators::StaticAllocator>;
	using GlobalRegionT = StaticRegion<Allocators::GlobalAllocator>;

	// Exported non-inline functions defined in KerbecsStatic.cpp ensure a single process-wide
	// Region instance across DLLs/EXEs, preventing overlapping region registrations.
	KERBECS_RUNTIME_API
		KERBECS_NODISCARD_MSG("Cannot discard persistent static region reference")
		PersistentRegionT& persistentRegion() noexcept;

	KERBECS_RUNTIME_API
		KERBECS_NODISCARD_MSG("Cannot discard global static region reference")
		GlobalRegionT& globalRegion() noexcept;

	// RAII teardown for KERBECS_PERSISTENT/KERBECS_GLOBAL slots using bound RegionFn NTTP.
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

// Two-level indirection so __COUNTER__ expands to a number before ## pasting -
// a single-level macro would paste the literal text "__COUNTER__" instead,
// which only breaks the moment a second static appears in the same TU.
#define KERBECS_CONCAT_IMPL(a, b) a##b
#define KERBECS_CONCAT(a, b) KERBECS_CONCAT_IMPL(a, b)

// KERBECS_STATIC_INIT_IMPL
//
// region is the accessor function name (unqualified call target,
// e.g. ::Kerbecs::StaticSupport::persistentRegion) - used both invoked
// (region().allocate<Type>()/construct(...)) and bare, as the
// KerbecsDestructor NTTP.
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

// KERBECS_PERSISTENT
//
// Allocates from the shared persistentRegion() (StaticZone-backed).
// Suitable for objects that must persist for the lifetime of the process.
#define KERBECS_PERSISTENT(Type, name, ...)                                         \
    ::Kerbecs::ShadowedMemory<Type> name;                                           \
    KERBECS_STATIC_INIT_IMPL(Type, name, ::Kerbecs::StaticSupport::persistentRegion, __COUNTER__, ##__VA_ARGS__)

#define KERBECS_PERSISTENT_DECL(Type, name)                                         \
    extern ::Kerbecs::ShadowedMemory<Type> name

// KERBECS_GLOBAL
//
// Allocates from the shared globalRegion() (GlobalZone-backed). Suitable for
// module-level singletons with controlled lifetime.
#define KERBECS_GLOBAL(Type, name, ...)                                             \
    static ::Kerbecs::ShadowedMemory<Type> name;                                    \
    KERBECS_STATIC_INIT_IMPL(Type, name, ::Kerbecs::StaticSupport::globalRegion, __COUNTER__, ##__VA_ARGS__)
