/*
* Copyright (c) 2025 StormWeaver
*
* This file is part of the Kerbecs Address Sanitizer API
*
* Licensed under the MIT License. You may obtain a copy of the License at
* https://opensource.org/licenses/MIT
*/

#include "KerbecsStatic.h"

#ifndef REGISTRY_CAPACITY
#error "REGISTRY_CAPACITY must be defined (see common/Kerbecs/CMakeLists.txt)"
#endif

namespace Kerbecs::StaticSupport {

	PersistentRegionT& persistentRegion() noexcept {
		auto& runtime = Runtime::instance();
		KERBECS_UNUSED(runtime.init());
		static PersistentRegionT s_Region(
			runtime.m_StaticAllocatorImpl,
			static_cast<size_t>(STATICZONE_SIZE) * Memory::GIBI_BYTE,
			REGISTRY_CAPACITY,
			runtime.m_StaticZone);
		return s_Region;
	}

	GlobalRegionT& globalRegion() noexcept {
		auto& runtime = Runtime::instance();
		KERBECS_UNUSED(runtime.init());
		static GlobalRegionT s_Region(
			runtime.m_GlobalAllocatorImpl,
			static_cast<size_t>(GLOBALZONE_SIZE) * Memory::GIBI_BYTE,
			REGISTRY_CAPACITY,
			runtime.m_GlobalZone);
		return s_Region;
	}

}
