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
#include  "Memory.h"
#include "MemoryZone.h"

#include <bit>
#include <cstddef>

#if defined(_WIN32)
#include <Windows.h>
#elif defined(__linux__)
#include <pthread.h>
#include <unistd.h>
#include <sys/mman.h>
#include <time.h>
#include <sched.h>
#endif

namespace Kerbecs::MemoryZone {
	bool KerbecsMemoryZone::init() {
		size_t totalBytes = SHADOWZONE_SIZE * Memory::GIBI_BYTE + GLOBALZONE_SIZE * Memory::GIBI_BYTE;
		bool reserved = true;
#if defined(_WIN32)
		m_MemoryZone = VirtualAlloc(std::bit_cast<void*>(MEMORY_ZONE_ADDRESS), totalBytes, MEM_RESERVE, PAGE_NOACCESS);
		reserved = m_MemoryZone != nullptr;
#elif defined(__linux__)
		m_MemoryZone = mmap(std::bit_cast<void*>(MEMORY_ZONE_ADDRESS), totalBytes, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		reserved = m_MemoryZone != MAP_FAILED;
#endif
		if (!reserved) m_MemoryZone = Memory::reserve(totalBytes);	
		if (!m_MemoryZone) return m_Initialized = false;
		m_ShadowZone = m_MemoryZone;
		m_GlobalZone = static_cast<std::byte*>(m_ShadowZone) + SHADOWZONE_SIZE * Memory::GIBI_BYTE;
		return m_Initialized = true;
	}
}