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
#include "AllocationRegistry.h"
#include "Kerbecs.h"
#include "KerbecsStats.h"

namespace Kerbecs::Quarantine {

	// QuarantineQueue stays a SINGLE SHARED instance across every Region
	// (v0.2 SS7.2), unlike AllocationRegistry which is now per-Region. The
	// epoch must cycle uniformly so the ">= 2 epoch increments" UAF-detection
	// window means the same thing everywhere, regardless of which Region a
	// block came from.
	//
	// m_BlockBase is written last (release) and read first (acquire) so any
	// thread observing a non-null m_BlockBase also sees all other fields.
	struct KERBECS_RUNTIME_API alignas(64) QuarantineEntry {
		size_t   m_BlockSize = 0;
		uint64_t m_Epoch = 0;
		void*    m_Allocator = nullptr;
		void   (*m_DeallocThunk)(void*, void*, size_t) = nullptr;

		// Stamped once at enqueue time (the same moment m_Allocator and
		// m_DeallocThunk are captured) - a plain, directly-typed pointer, no
		// type erasure needed since AllocationRegistry::retire(blockBase) is
		// already a concrete, template-parameter-free method. Lets
		// flushEligible dispatch the Quarantine->Dead CAS to the correct
		// Region's own registry with no search, no hash, at any scale - the
		// routing fact was already known the instant the block was
		// destroyed. (v0.2 SS7.2)
		Tracing::AllocationRegistry* m_OwningRegistry = nullptr;

		std::atomic<void*> m_BlockBase{ nullptr };
	};

	// Fixed-capacity ring buffer. enqueue: fetch_add on m_Tail per thread.
	// flushEligible: serialised by m_FlushLock to prevent concurrent m_Head races.
	struct KERBECS_RUNTIME_API QuarantineQueue {

		QuarantineQueue() = default;

		QuarantineQueue(const QuarantineQueue&) = delete;
		QuarantineQueue& operator=(const QuarantineQueue&) = delete;

		// v_Capacity must be a power of two.
		bool init(
			size_t        v_Capacity,
			KerbecsStats* p_Stats) noexcept;

		void shutdown() noexcept;

		bool enqueue(
			void*                         p_BlockBase,
			size_t                        v_BlockSize,
			uint64_t                      v_Epoch,
			void*                         p_Allocator,
			void                        (*p_DeallocThunk)(void*, void*, size_t),
			Tracing::AllocationRegistry* p_OwningRegistry) noexcept;

		size_t flushEligible(
			size_t v_MaxCount = SIZE_MAX,
			bool   v_Force = false) noexcept;

		size_t depth()    const noexcept;
		bool   full()     const noexcept;
		bool   empty()    const noexcept;
		size_t capacity() const noexcept { return m_Capacity; }

	private:
		void _retireSlot(QuarantineEntry& v_Entry) noexcept;

		KERBECS_NORETURN void _onSaturation() const noexcept;

		QuarantineEntry* m_Slots = nullptr;
		size_t                  m_Capacity = 0;

		alignas(64) std::atomic<size_t> m_Head{ 0 };
		alignas(64) std::atomic<size_t> m_Tail{ 0 };

		Tracing::Internal::SpinLock m_FlushLock;

		KerbecsStats* m_Stats = nullptr;
	};

}
