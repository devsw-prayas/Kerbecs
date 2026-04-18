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

namespace Kerbecs {

	struct KERBECS_RUNTIME_API KerbecsStats {
		std::atomic<size_t> m_TotalAllocated = 0; // incremented on shadowInit()
		std::atomic<size_t> m_TotalFreed = 0; // incremented on shadowDestroy()
		std::atomic<size_t> m_PeakUsage = 0; // high watermark of active bytes
		std::atomic<size_t> m_ActiveAllocations = 0; // current live allocation count
		std::atomic<size_t> m_ActiveBytes = 0;       // current live bytes
		std::atomic<size_t> m_TotalPoisonedBytes = 0; // net poisoned bytes across all shadows
		std::atomic<size_t> m_TotalViolations = 0; // incremented on every reportViolation()
		std::atomic<size_t> m_StaticAllocations = 0; // incremented on StaticRegion::allocate()
		std::atomic<size_t> m_QuarantinedBlocks = 0; // current blocks sitting in quarantine

		KerbecsStats() = default;
		KerbecsStats(const KerbecsStats&) = delete;
		KerbecsStats& operator=(const KerbecsStats&) = delete;
		KerbecsStats(KerbecsStats&&) = delete;
		KerbecsStats& operator=(KerbecsStats&&) = delete;
	};

	KERBECS_FORCEINLINE void statsOnInit(KerbecsStats* p_Stats, size_t v_Bytes) {
		if (!p_Stats) return;
		p_Stats->m_TotalAllocated.fetch_add(v_Bytes, std::memory_order_relaxed);
		p_Stats->m_ActiveAllocations.fetch_add(1, std::memory_order_relaxed);
		size_t activeBytes = p_Stats->m_ActiveBytes.fetch_add(v_Bytes, std::memory_order_relaxed) + v_Bytes;

		size_t peak = p_Stats->m_PeakUsage.load(std::memory_order_relaxed);
		while (activeBytes > peak &&
			!p_Stats->m_PeakUsage.compare_exchange_weak(peak, activeBytes, std::memory_order_relaxed));
	}

	KERBECS_FORCEINLINE void statsOnDestroy(KerbecsStats* p_Stats, size_t v_Bytes) {
		if (!p_Stats) return;
		p_Stats->m_TotalFreed.fetch_add(v_Bytes, std::memory_order_relaxed);
		p_Stats->m_ActiveAllocations.fetch_sub(1, std::memory_order_relaxed);
		p_Stats->m_ActiveBytes.fetch_sub(v_Bytes, std::memory_order_relaxed);
	}

	KERBECS_FORCEINLINE void statsOnPoison(KerbecsStats* p_Stats, size_t v_Bytes) {
		if (!p_Stats) return;
		p_Stats->m_TotalPoisonedBytes.fetch_add(v_Bytes, std::memory_order_relaxed);
	}

	KERBECS_FORCEINLINE void statsOnUnpoison(KerbecsStats* p_Stats, size_t v_Bytes) {
		if (!p_Stats) return;
		p_Stats->m_TotalPoisonedBytes.fetch_sub(v_Bytes, std::memory_order_relaxed);
	}

	KERBECS_FORCEINLINE void statsOnViolation(KerbecsStats* p_Stats) {
		if (!p_Stats) return;
		p_Stats->m_TotalViolations.fetch_add(1, std::memory_order_relaxed);
	}

	KERBECS_FORCEINLINE void statsOnStaticAlloc(KerbecsStats* p_Stats) {
		if (!p_Stats) return;
		p_Stats->m_StaticAllocations.fetch_add(1, std::memory_order_relaxed);
	}

	KERBECS_FORCEINLINE void statsOnQuarantineEnqueue(KerbecsStats* p_Stats) {
		if (!p_Stats) return;
		p_Stats->m_QuarantinedBlocks.fetch_add(1, std::memory_order_relaxed);
	}

	KERBECS_FORCEINLINE void statsOnQuarantineDequeue(KerbecsStats* p_Stats) {
		if (!p_Stats) return;
		p_Stats->m_QuarantinedBlocks.fetch_sub(1, std::memory_order_relaxed);
	}

}