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

// KERBECS_PERSISTENT / KERBECS_GLOBAL (v0.2 rebuild of the v0.1 macros).
//
// v0.1 allocated straight out of MemoryZone's shared StaticAllocator/
// GlobalAllocator via free shadowInit/shadowConstruct calls - there was no
// Region layer to go through. In v0.2, ShadowedMemory<T> is only ever
// constructible through a Region (its ctor is friend-only, reachable solely
// from Region::allocate), so these macros need one process-wide Region per
// zone to vend handles from: StaticSupport::persistentRegion() wraps
// KerbecsRuntime::m_StaticAllocatorImpl, StaticSupport::globalRegion() wraps
// m_GlobalAllocatorImpl.
//
// No Logger/Hasher/tag: v0.2 dropped both entirely (Region owns policy,
// ShadowedMemory<T> only ever needs T), so the old macros' `tag` parameter
// has no field left to land in and is not carried forward.
namespace Kerbecs::StaticSupport {

	// ThreadPolicy is fixed to Flexible for both static regions - objects
	// allocated through KERBECS_PERSISTENT/KERBECS_GLOBAL are process-lifetime
	// singletons, constructed and destroyed on whichever thread runs static
	// init/deinit, so Strict same-thread-free enforcement has no meaningful
	// caller to bind here. A subsystem that actually needs Strict should own
	// a private Region instead of going through these convenience macros.
	using PersistentRegionT = Region<Layout::StaticLayout, Shadow::Utils::ThreadPolicy::Flexible, Allocators::StaticAllocator>;
	using GlobalRegionT = Region<Layout::StaticLayout, Shadow::Utils::ThreadPolicy::Flexible, Allocators::GlobalAllocator>;

	// Defined (non-inline) in KerbecsStatic.cpp - a single translation unit
	// inside the Kerbecs library - rather than as header-inline function-
	// local statics. KERBECS_PERSISTENT/KERBECS_GLOBAL are meant to be used
	// from arbitrary consuming binaries; an inline definition here would give
	// every linking image (DLL/EXE) its own Region instance, each separately
	// registering an overlapping [StaticZone/GlobalZone base, +size) range
	// with the one shared KerbecsRuntime region-lookup table - the exact
	// per-translation-unit/per-image singleton split already hit once with
	// KerbecsRuntime itself (KERBECS_FORCEINLINE on a static singleton splits
	// it per TU). Exporting a single non-inline definition keeps exactly one
	// instance for the whole process, matching Runtime::instance().
	KERBECS_RUNTIME_API
		KERBECS_NODISCARD_MSG("Cannot discard persistent static region reference")
		PersistentRegionT& persistentRegion() noexcept;

	KERBECS_RUNTIME_API
		KERBECS_NODISCARD_MSG("Cannot discard global static region reference")
		GlobalRegionT& globalRegion() noexcept;

	// KerbecsDestructor
	//
	// RAII teardown for one KERBECS_PERSISTENT/KERBECS_GLOBAL slot, run at
	// static-deinit time. RegionFn is the region accessor (persistentRegion
	// or globalRegion) bound as a function-pointer NTTP so one template
	// serves both macros without duplicating the destructor body.
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

// KERBECS_CONCAT
//
// Two-level indirection so a __COUNTER__ argument is expanded to its numeric
// value BEFORE token-pasting, not after. counter is used with ## at every
// occurrence inside KERBECS_STATIC_INIT_IMPL, and per [cpp.subst] an argument
// is only macro-expanded before substitution at occurrences NOT adjacent to
// # or ## - since every occurrence here is a ## operand, passing __COUNTER__
// straight into a single-level ##-pasting macro pastes the literal text
// "__COUNTER__", not a number (harmless with one static per TU, a hard
// redefinition the moment a second one appears - this indirection avoids
// that entirely rather than relying on counter uniqueness per TU).
#define KERBECS_CONCAT_IMPL(a, b) a##b
#define KERBECS_CONCAT(a, b) KERBECS_CONCAT_IMPL(a, b)

// KERBECS_STATIC_INIT_IMPL
//
// Internal implementation macro shared by KERBECS_PERSISTENT and
// KERBECS_GLOBAL. region is the accessor function name (unqualified call
// target, e.g. ::Kerbecs::StaticSupport::persistentRegion) - used both
// invoked (region().allocate<Type>()/construct(...)) and bare, as the
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
