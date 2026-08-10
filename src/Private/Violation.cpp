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
#include "RegistryUtils.h"
#include "Violation.h"

namespace Kerbecs {

	namespace this_thread {
		namespace {
			// Fixed-capacity ring used as a stack: m_Top is the next write slot,
			// m_Count is the number of currently valid entries (capped at
			// VIOLATION_STACK_CAPACITY). Pushing past capacity advances m_Top onto
			// the slot popViolation would otherwise have returned last (the
			// bottom of the stack), so that entry is silently evicted.
			struct ViolationStack {
				Violation m_Entries[VIOLATION_STACK_CAPACITY]{};
				size_t    m_Top = 0;
				size_t    m_Count = 0;
			};

			thread_local ViolationStack t_ViolationStack{};
		}
	}

	namespace Internal {
		void pushViolation(const Violation& v_Violation) noexcept {
			auto& stack = this_thread::t_ViolationStack;
			stack.m_Entries[stack.m_Top] = v_Violation;
			stack.m_Top = (stack.m_Top + 1) % VIOLATION_STACK_CAPACITY;
			if (stack.m_Count < VIOLATION_STACK_CAPACITY)
				++stack.m_Count;
		}
	}

	bool popViolation(Violation& r_Out) noexcept {
		auto& stack = this_thread::t_ViolationStack;
		if (stack.m_Count == 0)
			return false;

		stack.m_Top = (stack.m_Top + VIOLATION_STACK_CAPACITY - 1) % VIOLATION_STACK_CAPACITY;
		r_Out = stack.m_Entries[stack.m_Top];
		--stack.m_Count;
		return true;
	}

	Violation makeViolation(ViolationKind v_Kind, void* p_Address, void* p_BlockBase, size_t v_BlockSize) noexcept {
		Violation v{};
		v.m_Kind = v_Kind;
		v.m_Address = p_Address;
		v.m_BlockBase = p_BlockBase;
		v.m_BlockSize = v_BlockSize;
		v.m_ThreadID = Tracing::Internal::currentThreadID();
		v.m_Timestamp = __rdtsc();
		return v;
	}

}
