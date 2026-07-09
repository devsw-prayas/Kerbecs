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
#include "RegistryUtils.h"

// Region-membership resolution (v0.2 SS5). A bare/wild address with no
// ShadowedMemory<T> behind it needs a way to ask "which Region, if any, owns
// this?" before any per-block lookup can even begin.
//
// The doc (SS5.2) describes reusing AllocationRegistry's hash+chain+range-check
// shape wholesale. That shape hashes an exact block-base pointer at insert
// time and looks it up by the SAME exact pointer later - AllocationRegistry
// never has to resolve an arbitrary INTERIOR address to a bucket, because
// every lookup already carries the block's base (via a resolved
// ShadowedMemory<T> or an already-known m_BlockBase).
//
// Region-membership resolution is structurally different: resolveRegion is
// handed an arbitrary wild address somewhere INSIDE a Region's range, not
// that Region's base. Hashing that wild address can't deterministically land
// in the same bucket a RegionRecord was filed under by ITS base address - a
// Region's range spans far more values than a single hash bucket represents.
// Given the doc's own sizing note (Region count is "realistically a
// handful", the 1024 ceiling is headroom, never an expected count), this
// implementation resolves by a linear scan over the small registered-Region
// list instead of pretending to bucket-hash a range-spanning record. This is
// O(region count) - equivalent to "trivially short chain walk" at the scale
// the doc describes, just without the hash indirection that wouldn't
// actually narrow the search for this particular lookup shape.
namespace Kerbecs::Tracing {

	// RegionRecord - registry-internal only, never exposed publicly (v0.2 SS5.3).
	//
	// Deviates from the doc's minimal 3-pointer/24-byte sketch
	// (m_RegionPtr/m_ShadowMapBase/m_MetadataMapBase only): the doc's own
	// range-check step ("range-check the address against that Region's real
	// [base, base+size)") needs an actual base+size to check against, which
	// three pointers alone don't carry. m_RegionBase/m_RegionSize are added
	// here in the same spirit the doc already uses for the other two fields
	// ("mirrors Region::m_ShadowBlobPtr", "mirrors Region::m_MetadataMapBase") -
	// mirroring Region::m_Size (and the base address of what it wraps) rather
	// than reaching back through a type-erased Region* on every lookup.
	// Immutable after registration; Regions are never recycled, so no
	// generation field is needed (matches the doc exactly on this point).
	struct alignas(64) RegionRecord {
		void* m_RegionPtr = nullptr;       // opaque handle back to the owning Region (type-erased - Region<L,T,A> varies per instantiation)
		void* m_ShadowMapBase = nullptr;   // mirrors Region::m_ShadowBlobPtr
		void* m_MetadataMapBase = nullptr; // mirrors Region::m_MetadataMapBase
		void* m_RegionBase = nullptr;      // base address of the Region's wrapped allocator's VA
		size_t m_RegionSize = 0;           // mirrors Region::m_Size - the range-check bound
	};

	// registerRegionRecord
	//
	// Called once by KerbecsRuntime::registerRegion at Region construction
	// time. p_Region is stored opaquely - callers of resolveRegion never
	// need the concrete Region<Layout,ThreadPolicy,Allocator> type, only the
	// pointer identity to hand back to whatever violation-reporting path
	// asked "which Region owns this address".
	KERBECS_RUNTIME_API bool registerRegionRecord(
		void* p_Region,
		void* p_ShadowMapBase,
		void* p_MetadataMapBase,
		void* p_RegionBase,
		size_t v_RegionSize) noexcept;

	// resolveRegion
	//
	// Linear scan over the registered-Region list, range-checking p_Address
	// against each candidate's [m_RegionBase, m_RegionBase + m_RegionSize).
	// First match wins; exhausting the list means the address is genuinely
	// outside everything Kerbecs manages (v0.2 SS5.2 intent; see the
	// linear-scan-vs-hash-bucket note above this namespace for why this
	// doesn't bucket-hash the way AllocationRegistry does).
	KERBECS_RUNTIME_API KERBECS_NODISCARD_MSG("Cannot discard region resolution result")
		const RegionRecord* resolveRegion(const void* p_Address) noexcept;

	KERBECS_RUNTIME_API bool initRegionTable() noexcept;
	KERBECS_RUNTIME_API void shutdownRegionTable() noexcept;
}
