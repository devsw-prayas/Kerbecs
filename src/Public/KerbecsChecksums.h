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
#include "KerbecsRuntime.h"
#include "ShadowUtils.h"

#include "KerbecsEnforcements.h"

namespace Kerbecs::Checksums {
	template<typename HA>
		requires Enforcement::HashAccumulatorConcept<HA>
	uint64_t computeMetadataChecksum(
		HA* p_Hasher,
		uint64_t v_AllocatorID,
		uint64_t v_ThreadID,
		void* p_BlockBase,
		size_t   v_TotalSize,
		size_t   v_TotalCommitted,
		size_t   v_TotalPoisoned) noexcept {
		p_Hasher->reset();
		p_Hasher->add(v_AllocatorID);
		p_Hasher->add(v_ThreadID);
		p_Hasher->add(reinterpret_cast<uint64_t>(p_BlockBase));
		p_Hasher->add(static_cast<uint64_t>(v_TotalSize));
		p_Hasher->add(static_cast<uint64_t>(v_TotalCommitted));
		p_Hasher->add(static_cast<uint64_t>(v_TotalPoisoned));
		return p_Hasher->finalize();
	}

	template<typename HA>
		requires Enforcement::HashAccumulatorConcept<HA>
	bool initEnhancedMetadata(
		HA* p_Hasher,
		Runtime::EnhancedMetaData* p_Leading,
		Runtime::EnhancedMetaData* p_Trailing,
		size_t                         v_TotalSize,
		uint64_t                       v_AllocatorID,
		uint64_t                       v_ThreadID,
		void* p_BlockBase) noexcept {
		if (!p_Hasher || !p_Leading || !p_Trailing) return false;

		uint64_t allocatorHash = v_AllocatorID;
		uint64_t threadHash = v_ThreadID;
		uint64_t checksum = computeMetadataChecksum(
			p_Hasher,
			allocatorHash,
			threadHash,
			p_BlockBase,
			v_TotalSize,
			v_TotalSize,  // TotalCommitted = TotalSize at init
			v_TotalSize); // TotalPoisoned  = TotalSize at init

		p_Leading->m_TotalSize = v_TotalSize;
		p_Leading->m_TotalCommitted = v_TotalSize;
		p_Leading->m_TotalPoisoned = v_TotalSize;
		p_Leading->m_AllocatorHash = allocatorHash;
		p_Leading->m_ThreadHash = threadHash;
		p_Leading->m_Checksum = checksum;

		*p_Trailing = *p_Leading;

		return true;
	}


	inline bool initNormalMetadata(
		Runtime::NormalMetaData* p_Meta,
		size_t                      v_TotalSize,
		uint64_t                    v_AllocatorID) noexcept {
		if (!p_Meta) return false;

		p_Meta->m_TotalSize = v_TotalSize;
		p_Meta->m_TotalCommitted = v_TotalSize;
		p_Meta->m_TotalPoisoned = v_TotalSize;
		p_Meta->m_AllocatorHash = v_AllocatorID;

		return true;
	}

	template<typename HA>
		requires Enforcement::HashAccumulatorConcept<HA>
	bool verifyEnhancedMetadata(
		HA* p_Hasher,
		const Runtime::EnhancedMetaData* p_Leading,
		const Runtime::EnhancedMetaData* p_Trailing,
		size_t                               v_ExpectedTotalSize,
		uint64_t                             v_ExpectedAllocatorID,
		uint64_t                             v_ExpectedThreadID,
		void* p_BlockBase,
		Shadow::Utils::ThreadPolicy                  v_Policy) noexcept {
		if (!p_Hasher || !p_Leading || !p_Trailing) return false;

		if (p_Leading->m_TotalSize != v_ExpectedTotalSize)
			return false;

		if (p_Leading->m_AllocatorHash != v_ExpectedAllocatorID)
			return false;

		if (v_Policy == Shadow::Utils::ThreadPolicy::Strict) {
			if (p_Leading->m_ThreadHash != v_ExpectedThreadID)
				return false;
		}

		uint64_t expected = computeMetadataChecksum(
			p_Hasher,
			p_Leading->m_AllocatorHash,
			p_Leading->m_ThreadHash,
			p_BlockBase,
			p_Leading->m_TotalSize,
			p_Leading->m_TotalCommitted,
			p_Leading->m_TotalPoisoned);

		if (p_Leading->m_Checksum != expected)return false;
		return true;
	}

	KERBECS_FORCEINLINE bool verifyNormalMetadata(
		const Runtime::NormalMetaData* p_Meta,
		size_t                            v_ExpectedTotalSize,
		uint64_t                          v_ExpectedAllocatorID) noexcept {
		if (!p_Meta) return false;
		if (p_Meta->m_TotalSize != v_ExpectedTotalSize)    return false;
		if (p_Meta->m_AllocatorHash != v_ExpectedAllocatorID)  return false;
		return true;
	}
}
