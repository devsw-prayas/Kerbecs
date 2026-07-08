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
#include "Violation.h"

// No ShadowMapConcept (v0.2 SS6 - shadow map concept removed entirely;
// poison/unpoison/toShadow are free functions over a blob + range).

namespace Kerbecs::Enforcement {

	template<typename T>
	concept LoggerConcept = requires(T logger, const Violation & v) {
		{ logger.report(v) } -> std::same_as<void>;
	};

	template<typename T>
	concept LayoutPolicyConcept = requires(
		void* block,
		size_t blockSize,
		size_t payloadSize,
		size_t align,
		const typename T::Offsets & offsets) {
		typename T::Offsets;
		{ T::blockSize(payloadSize, align) } -> std::same_as<size_t>;
		{ T::place(block, blockSize, payloadSize, align) } -> std::same_as<typename T::Offsets>;
		{ T::verifyGuards(block, offsets, blockSize) } -> std::same_as<bool>;
	};

	template<typename T>
	concept HashAccumulatorConcept = requires(T h, uint64_t v) {
		{ h.add(v) }     -> std::same_as<void>;
		{ h.finalize() } -> std::same_as<uint64_t>;
		{ h.reset() }    -> std::same_as<void>;
	};

	template<typename A>
	concept AllocatorConcept =
		requires(A a, size_t bytes, size_t align, void* p) {
			{ a.allocate(bytes, align) } noexcept -> std::same_as<void*>;
			{ a.deallocate(p, bytes) } noexcept -> std::same_as<void>;
	};
}
