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

// Linear scan resolves interior addresses to a RegionRecord — range-spanning
// addresses can't bucket-hash like exact block bases, and region counts are small.
namespace Kerbecs::Tracing {

	struct alignas(64) RegionRecord {
		void* m_RegionPtr = nullptr;
		void* m_ShadowMapBase = nullptr;
		void* m_MetadataMapBase = nullptr;
		void* m_RegionBase = nullptr;
		size_t m_RegionSize = 0;
	};

	KERBECS_RUNTIME_API bool registerRegionRecord(
		void* p_Region,
		void* p_ShadowMapBase,
		void* p_MetadataMapBase,
		void* p_RegionBase,
		size_t v_RegionSize) noexcept;

	KERBECS_RUNTIME_API KERBECS_NODISCARD_MSG("Cannot discard region resolution result")
		const RegionRecord* resolveRegion(const void* p_Address) noexcept;

	KERBECS_RUNTIME_API bool initRegionTable() noexcept;
	KERBECS_RUNTIME_API void shutdownRegionTable() noexcept;
}
