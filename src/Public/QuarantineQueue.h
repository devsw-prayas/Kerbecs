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
#include "KerbecsStats.h"
#include "AllocationRegistry.h"

#include <atomic>
#include <cstddef>
#include <cstdint>

namespace Kerbecs::Quarantine {
	struct KERBECS_RUNTIME_API alignas(16) QuarantineEntry {
		void* m_BlockBase = nullptr;
		size_t m_BlockSize = 0;
	};
	

	struct KERBECS_RUNTIME_API QuarantineQueue {
		using FreeCallback = void(*)(void* p_BlockBase, size_t v_BlockSize) noexcept;
		QuarantineQueue() = default;

		QuarantineQueue(const QuarantineQueue&) = delete;
		QuarantineQueue& operator=(const QuarantineQueue&) = delete;
		QuarantineQueue(QuarantineQueue&&) = delete;
		QuarantineQueue& operator=(QuarantineQueue&&) = delete;


		KERBECS_NODISCARD_MSG("Cannot discard quarantine queue init result")
			bool init(
				QuarantineEntry* p_Slots,
				size_t           v_Capacity,
				Tracing::AllocationRegistry* p_Registry,
				KerbecsStats* p_Stats,
				FreeCallback     p_FreeCallback) noexcept;


		KERBECS_NODISCARD_MSG("Cannot discard enqueue result")
			bool enqueue(void* p_BlockBase, size_t v_BlockSize) noexcept;

		size_t flush(size_t v_MaxCount = SIZE_MAX) noexcept;

		bool flushOne() noexcept;

		KERBECS_NODISCARD_MSG("Cannot discard quarantine depth")
			size_t depth() const noexcept;

		KERBECS_NODISCARD_MSG("Cannot discard quarantine capacity")
			size_t capacity() const noexcept { return m_Capacity; }

		KERBECS_NODISCARD_MSG("Cannot discard quarantine full state")
			bool full() const noexcept;

		KERBECS_NODISCARD_MSG("Cannot discard quarantine empty state")
			bool empty() const noexcept;

	private:
		QuarantineEntry* m_Slots = nullptr;
		size_t              m_Capacity = 0;        // power of two

		alignas(64) std::atomic<size_t> m_Head = 0;
		alignas(64) std::atomic<size_t> m_Tail = 0;

		Tracing::AllocationRegistry* m_Registry = nullptr;
		KerbecsStats* m_Stats = nullptr;
		FreeCallback        m_FreeCallback = nullptr;

		void _retireSlot(QuarantineEntry& v_Entry) const noexcept;
	};

}