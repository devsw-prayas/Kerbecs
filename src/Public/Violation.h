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
	enum class KERBECS_RUNTIME_API ViolationKind : uint8_t {
		DoubleFree,          // destroy() called on already-destroyed block
		UseAfterFree,        // access to tombstoned or quarantined block
		UseBeforeInit,       // access to fully poisoned (never constructed) block
		BufferOverflow,      // redzone or canary pattern corrupted
		OverlapDetected,     // two tracked allocations overlap in VA
		LeakDetected,        // live allocation at shutdown
		MetadataCorruption,  // checksum or mirror mismatch in EnhancedMetaData
		AlignmentViolation,  // construct<T>() ptr % alignof(T) != 0
		SizeOverflow,        // blockSize<T>() multiplication overflowed
		WildPointer,         // access to address not in any Region's AllocationRegistry
		ThreadOwnership,      // destroy() called from wrong thread (Strict policy)
		QuarantineSaturation,     // quarantine ring buffer is full - fail fast
		RetiredBoundaryViolation,  // access to a Retiring block by a non-owner thread - fail fast
		UndefinedWildPointerAccess, // live access lands inside an engine-owned region the caller was never given a handle to
		EngineMemoryAccessViolation, // diagnostic escalation of UndefinedWildPointerAccess, gated by DiagnosticAccess policy
		None
	};

	struct KERBECS_RUNTIME_API Violation {
		ViolationKind m_Kind = ViolationKind::None;
		const char* m_Name = nullptr;         // named allocation tag (string literal, not owned)
		void* m_Address = nullptr;
		void* m_BlockBase = nullptr;
		size_t        m_BlockSize{};
		uint64_t      m_Timestamp{};    // __rdtsc() at detection time
		uint32_t      m_ThreadID{};
	};

	// Per-thread capacity of the violation stack (see pushViolation/popViolation
	// below). Fixed, no heap allocation - a burst past this size evicts the
	// oldest not-yet-popped entry rather than growing or blocking.
	inline constexpr size_t VIOLATION_STACK_CAPACITY = 32;

	namespace Internal {
		// Called by every detection site; not part of the public query surface -
		// callers drain through popViolation() below.
		KERBECS_RUNTIME_API void pushViolation(const Violation& v_Violation) noexcept;
	}

	// Pops the most recently pushed, not-yet-popped Violation on the calling
	// thread into r_Out (LIFO). Returns false and leaves r_Out untouched if this
	// thread's stack is empty - drain it in a loop to walk the whole backlog.
	KERBECS_RUNTIME_API
		KERBECS_NODISCARD_MSG("Cannot discard whether a violation was popped")
		bool popViolation(Violation& r_Out) noexcept;

	// Builds a Violation with its thread id/timestamp stamped, for every
	// detection site to push via Internal::pushViolation - keeps that stamping
	// logic (currentThreadID()/__rdtsc()) in one place instead of duplicated at
	// every call site in Region.h/ShadowedMemory.h.
	KERBECS_RUNTIME_API
		KERBECS_NODISCARD_MSG("Cannot discard constructed violation")
		Violation makeViolation(ViolationKind v_Kind, void* p_Address, void* p_BlockBase, size_t v_BlockSize) noexcept;
}
