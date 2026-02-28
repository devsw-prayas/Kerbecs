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
#include "KerbecsMemory.h"
#include "Violation.h"
namespace Kerbecs::Tracing {

	enum class KERBECS_RUNTIME_API AllocationState : uint8_t {
		Empty = 0,
		Live = 1,
		Quarantine = 2,
		Dead = 3
	};

	struct KERBECS_RUNTIME_API alignas(128) RegistryEntry {
		void* m_BlockBase = nullptr;
		void* m_UserPtr = nullptr;  
		size_t      m_BlockSize = 0;     
		size_t      m_UserSize = 0;    
		uint64_t    m_AllocatorID = 0;        
		StackTrace  m_AllocTrace = {}; 
		StackTrace  m_FreeTrace = {};      
		const char* m_Name = nullptr;  
		uint32_t    m_ThreadID = 0;     
		std::atomic<AllocationState> m_State = AllocationState::Empty;

	};

	struct KERBECS_RUNTIME_API AllocationRegistry {

		AllocationRegistry() = default;

		AllocationRegistry(const AllocationRegistry&) = delete;
		AllocationRegistry& operator=(const AllocationRegistry&) = delete;
		AllocationRegistry(AllocationRegistry&&) = delete;
		AllocationRegistry& operator=(AllocationRegistry&&) = delete;

		KERBECS_NODISCARD_MSG("Cannot discard registry init result")
			bool init(RegistryEntry* p_Slots, size_t v_Capacity) noexcept;

		KERBECS_NODISCARD_MSG("Cannot discard insert result")
			bool insert(
				void* p_BlockBase,
				void* p_UserPtr,
				size_t      v_BlockSize,
				size_t      v_UserSize,
				uint64_t    v_AllocatorID,
				uint32_t    v_ThreadID,
				const char* p_Name,
				const StackTrace& v_AllocTrace) noexcept;

		KERBECS_NODISCARD_MSG("Cannot discard remove result")
			bool remove(void* p_BlockBase, const StackTrace& v_FreeTrace)const noexcept;


		KERBECS_NODISCARD_MSG("Cannot discard retire result")
			bool retire(void* p_BlockBase) noexcept;


		KERBECS_NODISCARD_MSG("Cannot discard find result")
			const RegistryEntry* find(const void* p_BlockBase) const noexcept;

		KERBECS_NODISCARD_MSG("Cannot discard find result")
			RegistryEntry* find(const void* p_BlockBase) noexcept;


		KERBECS_NODISCARD_MSG("Cannot discard range find result")
			const RegistryEntry* findRange(const void* p_Address) const noexcept;

		template<typename Fn>
		void reportLeaks(Fn&& v_Callback) const noexcept {
			if (!m_Slots || m_Capacity == 0) return;
			for (size_t i = 0; i < m_Capacity; i++) {
				const RegistryEntry& entry = m_Slots[i];
				if (entry.m_State.load(std::memory_order_acquire) == AllocationState::Live)
					v_Callback(entry);
			}
		}

		KERBECS_NODISCARD_MSG("Cannot discard live count")
			size_t liveCount() const noexcept;

		KERBECS_NODISCARD_MSG("Cannot discard quarantine count")
			size_t quarantineCount() const noexcept;

		KERBECS_NODISCARD_MSG("Cannot discard capacity")
			size_t capacity() const noexcept { return m_Capacity; }

		KERBECS_NODISCARD_MSG("Cannot discard load factor")
			float loadFactor() const noexcept;

	private:
		RegistryEntry* m_Slots = nullptr;
		size_t               m_Capacity = 0;      // must be power of two
		std::atomic<size_t>  m_Count = 0;       // live + quarantine entries

		KERBECS_FORCEINLINE size_t _hash(const void* p_BlockBase) const noexcept {
			uintptr_t key = reinterpret_cast<uintptr_t>(p_BlockBase) >> 4;
			key *= 0x9e3779b97f4a7c15ULL;
			return static_cast<size_t>(key >> (64 - _log2(m_Capacity)));
		}

		KERBECS_FORCEINLINE static size_t _log2(size_t v) noexcept {
			size_t r = 0;
			while (v >>= 1) r++;
			return r;
		}

		size_t _probe(const void* p_BlockBase) const noexcept;
	};

} 