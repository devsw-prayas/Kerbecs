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

	// QuarantineEntry
	//
	// Represents one in-flight block sitting in the quarantine ring buffer.
	//
	// Field ordering is critical for correctness under concurrent access:
	// m_BlockBase is written LAST at enqueue (with release) and read FIRST
	// at flush (with acquire). All other fields must be fully written before
	// m_BlockBase is stored so that any thread that observes a non-null
	// m_BlockBase also observes a fully consistent entry.
	//
	// m_Allocator / m_DeallocThunk are the type-erased deallocation pair
	// stamped at enqueue time by shadowDestroy where the concrete allocator
	// type is still in scope. The quarantine calls:
	//   m_DeallocThunk(m_Allocator, blockBase, blockSize)
	// at flush time without ever knowing the allocator type.
	struct KERBECS_RUNTIME_API alignas(64) QuarantineEntry {
		// Written before m_BlockBase - plain (non-atomic) fields.
		size_t   m_BlockSize = 0;
		uint64_t m_Epoch = 0;
		void*    m_Allocator = nullptr;
		void   (*m_DeallocThunk)(void*, void*, size_t) = nullptr;

		// Associated registry node for O(1) retirement.
		Tracing::Internal::RegistryNode* m_Node = nullptr;

		// Published last with release. A non-null load with acquire
		// guarantees all fields above are visible.
		std::atomic<void*> m_BlockBase{ nullptr };
	};
	
	// QuarantineQueue
	//
	// Fixed-capacity ring buffer holding blocks between logical free and
	// physical reclamation. Provides a use-after-free detection window
	// controlled by the epoch system (2-epoch minimum delay).
	//
	// The queue self-manages its slot array - Memory::allocate is called in
	// init() and Memory::release is called in shutdown(). No external slot
	// storage is required.
	//
	// The queue holds no reference to AllocationRegistry. State transitions
	// (Quarantine -> Dead) are performed directly via the NodePoolSegment
	// passed into flushEligible by the caller.
	//
	// Concurrency:
	//   enqueue  - fetch_add on m_Tail gives each thread its own slot index.
	//              Non-atomic fields written before atomic m_BlockBase store.
	//              Saturation (slot already occupied) is a fail-fast violation.
	//   flushEligible - protected by m_FlushLock (SpinLock) to prevent
	//              concurrent callers racing on m_Head advancement.
	//   depth / full / empty - advisory only, may be stale by the time
	//              the caller acts on the result.
	struct KERBECS_RUNTIME_API QuarantineQueue {

		QuarantineQueue() = default;

		QuarantineQueue(const QuarantineQueue&) = delete;
		QuarantineQueue& operator=(const QuarantineQueue&) = delete;

		// Self-allocates the slot array via Memory::allocate.
		// v_Capacity must be a power of two.
		bool init(
			size_t        v_Capacity,
			KerbecsStats* p_Stats) noexcept;

		// Releases the self-allocated slot array via Memory::release.
		void shutdown() noexcept;

		// Enqueue a block into the quarantine ring buffer.
		// Non-atomic fields (m_BlockSize, m_Epoch, m_Allocator, m_DeallocThunk)
		// are written before the atomic store of m_BlockBase (release) to
		// guarantee visibility to any thread that acquires m_BlockBase.
		// Saturation (slot still occupied) fires QuarantineSaturation
		// violation and traps - fail fast, no graceful eviction.
		bool enqueue(
			void*                            p_BlockBase,
			size_t                           v_BlockSize,
			uint64_t                         v_Epoch,
			void*                            p_Allocator,
			void                           (*p_DeallocThunk)(void*, void*, size_t),
			Tracing::Internal::RegistryNode* p_Node = nullptr) noexcept;

		// Flush all entries whose epoch satisfies:
		//   slot.m_Epoch + 2 <= v_CurrentEpoch
		// For each eligible entry:
		//   1. CAS Quarantine -> Dead on the node via NodePoolSegment scan.
		//   2. Call m_DeallocThunk(m_Allocator, blockBase, blockSize).
		//   3. Null the entry and advance m_Head.
		// Protected by m_FlushLock to prevent concurrent callers racing on
		// m_Head. v_MaxCount caps the number of entries retired per call.
		// Pass SIZE_MAX to drain the queue completely (used at teardown).
		size_t flushEligible(
			Tracing::NodePoolSegment       v_Segment,
			size_t                         v_MaxCount = SIZE_MAX,
			bool                           v_Force = false) noexcept;

		size_t depth()    const noexcept;
		bool   full()     const noexcept;
		bool   empty()    const noexcept;
		size_t capacity() const noexcept { return m_Capacity; }

	private:
		void _retireSlot(
			QuarantineEntry& v_Entry,
			Tracing::NodePoolSegment v_Segment) noexcept;

		// Fail-fast saturation handler. Fires QuarantineSaturation violation
		// and traps. Never returns.
		KERBECS_NORETURN void _onSaturation() const noexcept;

		QuarantineEntry* m_Slots = nullptr;
		size_t                  m_Capacity = 0;

		alignas(64) std::atomic<size_t> m_Head{ 0 };
		alignas(64) std::atomic<size_t> m_Tail{ 0 };

		// Guards flushEligible to prevent concurrent callers racing on m_Head.
		Tracing::Internal::SpinLock m_FlushLock;

		KerbecsStats* m_Stats = nullptr;
	};

} 