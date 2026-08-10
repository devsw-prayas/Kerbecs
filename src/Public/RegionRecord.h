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

// Region-membership resolution: Linear scan over registered regions resolves
// arbitrary interior addresses to a RegionRecord. Simple scan is used because range-spanning
// addresses cannot bucket-hash like exact block bases, and region counts are small.
namespace Kerbecs::Tracing {

	// RegionRecord - registry-internal tuple containing Region base, size,
	// shadow/metadata map bases, and opaque Region pointer. Immutable after registration.
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
	// outside everything Kerbecs manages (see the
	// linear-scan-vs-hash-bucket note above this namespace for why this
	// doesn't bucket-hash the way AllocationRegistry does).
	KERBECS_RUNTIME_API KERBECS_NODISCARD_MSG("Cannot discard region resolution result")
		const RegionRecord* resolveRegion(const void* p_Address) noexcept;

	KERBECS_RUNTIME_API bool initRegionTable() noexcept;
	KERBECS_RUNTIME_API void shutdownRegionTable() noexcept;
}
