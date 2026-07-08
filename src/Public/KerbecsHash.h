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

#include "KerbecsEnforcements.h"

// Metadata-checksum hash accumulators (the H template parameter wherever a
// HashAccumulatorConcept is required - Region's metadata checksums, etc).
//
// Not to be confused with the Fibonacci/golden-ratio bucket hash used by
// AllocationRegistry::_index and the RegionRecord lookup table (v0.2 SS5.2) -
// that scheme is address-bucket hashing, hardcoded per-class where it's used,
// not a swappable accumulator.

namespace Kerbecs::Hash {

	struct KERBECS_RUNTIME_API SplitMix64Hash {
		uint64_t m_State = 0;

		void add(uint64_t v_Value) noexcept {
			m_State ^= v_Value;
			m_State += 0x9e3779b97f4a7c15ULL;
			m_State = (m_State ^ (m_State >> 30)) * 0xbf58476d1ce4e5b9ULL;
			m_State = (m_State ^ (m_State >> 27)) * 0x94d049bb133111ebULL;
			m_State = m_State ^ (m_State >> 31);
		}

		uint64_t finalize() noexcept {
			return m_State;
		}

		void reset() noexcept {
			m_State = 0;
		}
	};

	struct KERBECS_RUNTIME_API Murmur3Mix64Hash {
		uint64_t m_State = 0;

		void add(uint64_t v_Value) noexcept {
			m_State ^= v_Value;
			m_State ^= m_State >> 33;
			m_State *= 0xff51afd7ed558ccdULL;
			m_State ^= m_State >> 33;
			m_State *= 0xc4ceb9fe1a85ec53ULL;
			m_State ^= m_State >> 33;
		}

		uint64_t finalize() noexcept {
			return m_State;
		}

		void reset() noexcept {
			m_State = 0;
		}
	};

	struct KERBECS_RUNTIME_API WyHash64 {
		uint64_t m_State = 0;
		uint64_t m_Seed = 0xa0761d6478bd642fULL;

		void add(uint64_t v_Value) noexcept {
			m_State ^= v_Value;
			uint64_t a = m_State ^ m_Seed;
			uint64_t b = m_State * m_Seed;

			uint64_t hi = 0;
			uint64_t lo = _umul128(a, b, &hi);
			m_State = lo ^ hi;
		}

		uint64_t finalize() noexcept {
			return m_State;
		}

		void reset() noexcept {
			m_State = 0;
			m_Seed = 0xa0761d6478bd642fULL;
		}
	};


	static_assert(Enforcement::HashAccumulatorConcept<SplitMix64Hash>);
	static_assert(Enforcement::HashAccumulatorConcept<Murmur3Mix64Hash>);
	static_assert(Enforcement::HashAccumulatorConcept<WyHash64>);

}
