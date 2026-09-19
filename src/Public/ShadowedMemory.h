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
#include "KerbecsEnforcements.h"
#include "ShadowUtils.h"
#include "Violation.h"

namespace Kerbecs {
	template<typename LayoutT, Shadow::Utils::ThreadPolicy ThreadPolicyT, typename AllocatorT>
		requires Enforcement::LayoutPolicyConcept<LayoutT> && Enforcement::AllocatorConcept<AllocatorT>
	class Region;

	template<typename T> class ShadowedMemory;

	template<typename T>
	KERBECS_NODISCARD_MSG("Cannot discard shadow state")
		Shadow::Utils::MemoryState shadowStateOf(const ShadowedMemory<T>& v_Handle, size_t v_Size) noexcept;

	template<typename T>
	class ShadowedMemory final {
	public:
		ShadowedMemory() noexcept = default;
		ShadowedMemory(std::nullptr_t) noexcept {}

		ShadowedMemory(const ShadowedMemory&) noexcept = default;
		ShadowedMemory& operator=(const ShadowedMemory&) noexcept = default;
		ShadowedMemory(ShadowedMemory&&) noexcept = default;
		ShadowedMemory& operator=(ShadowedMemory&&) noexcept = default;
		~ShadowedMemory() = default;

		KERBECS_NODISCARD_MSG("Cannot discard dereferenced reference")
			T& operator*() const noexcept {
			_check();
			return *static_cast<T*>(m_PayloadPtr);
		}

		KERBECS_NODISCARD_MSG("Cannot discard dereferenced pointer")
			T* operator->() const noexcept {
			_check();
			return static_cast<T*>(m_PayloadPtr);
		}

		operator T* () const noexcept {
			_check();
			return static_cast<T*>(m_PayloadPtr);
		}

		friend bool operator==(const ShadowedMemory& v_Lhs, const ShadowedMemory& v_Rhs) noexcept {
			return v_Lhs.m_PayloadPtr == v_Rhs.m_PayloadPtr && v_Lhs.m_Generation == v_Rhs.m_Generation;
		}
		friend bool operator!=(const ShadowedMemory& v_Lhs, const ShadowedMemory& v_Rhs) noexcept {
			return !(v_Lhs == v_Rhs);
		}

		KERBECS_NODISCARD_MSG("Cannot discard offset handle")
			ShadowedMemory operator+(ptrdiff_t v_Index) const noexcept {
			if (!m_PayloadPtr || !m_MetaPtr)
				return ShadowedMemory{};

			const auto* info = static_cast<const Runtime::AccessInfo*>(m_MetaPtr);
			const ptrdiff_t byteOffset = v_Index * static_cast<ptrdiff_t>(sizeof(T));
			const ptrdiff_t newOffsetEnd = byteOffset + static_cast<ptrdiff_t>(sizeof(T));

			if (newOffsetEnd < 0 || byteOffset < 0 || static_cast<size_t>(newOffsetEnd) > info->m_UserSize) {
				statsOnViolation(&Runtime::instance().m_Stats);
				Internal::pushViolation(makeViolation(
					ViolationKind::BufferOverflow,
					static_cast<std::byte*>(m_PayloadPtr) + byteOffset,
					m_PayloadPtr,
					info->m_UserSize));
				return ShadowedMemory{};
			}

			return ShadowedMemory(
				m_MetaPtr,
				static_cast<std::byte*>(m_PayloadPtr) + byteOffset,
				m_ShadowPtr,
				m_Generation);
		}

	private:
		template<typename LayoutT, Shadow::Utils::ThreadPolicy ThreadPolicyT, typename AllocatorT>
			requires Enforcement::LayoutPolicyConcept<LayoutT> && Enforcement::AllocatorConcept<AllocatorT>
		friend class Region;

		template<typename U>
		friend Shadow::Utils::MemoryState shadowStateOf(const ShadowedMemory<U>& v_Handle, size_t v_Size) noexcept;

		ShadowedMemory(void* p_MetaPtr, void* p_PayloadPtr, void* p_ShadowPtr, uint64_t v_Generation) noexcept
			: m_MetaPtr(p_MetaPtr), m_PayloadPtr(p_PayloadPtr), m_ShadowPtr(p_ShadowPtr), m_Generation(v_Generation) {}

		void _check() const noexcept {
			if (!m_PayloadPtr || !m_MetaPtr) return;

			const auto* info = static_cast<const Runtime::AccessInfo*>(m_MetaPtr);
			if (info->m_Generation.load(std::memory_order_acquire) != m_Generation) {
				statsOnViolation(&Runtime::instance().m_Stats);
				Internal::pushViolation(makeViolation(ViolationKind::UseAfterFree, m_PayloadPtr, m_PayloadPtr, 0));
				KERBECS_TRAP();
			}
		}

		void* m_MetaPtr = nullptr;
		void* m_PayloadPtr = nullptr;
		void* m_ShadowPtr = nullptr;
		uint64_t m_Generation = 0;
	};

	template<typename T>
	Shadow::Utils::MemoryState shadowStateOf(const ShadowedMemory<T>& v_Handle, size_t v_Size) noexcept {
		T* payload = static_cast<T*>(v_Handle.m_PayloadPtr);
		if (!payload)
			return Shadow::Utils::MemoryState::CORRUPTED;

		const auto* bytes = reinterpret_cast<const uint8_t*>(payload);
		size_t poisoned = 0;
		for (size_t i = 0; i < v_Size; ++i)
			if (bytes[i] == static_cast<uint8_t>(Runtime::POISONED))
				++poisoned;

		if (poisoned == v_Size)                return Shadow::Utils::MemoryState::UNINITIALIZED;
		if (poisoned > 0 && poisoned < v_Size)  return Shadow::Utils::MemoryState::CORRUPTED;
		if (Shadow::Utils::verifyTombstone(bytes, v_Size)) return Shadow::Utils::MemoryState::DESTROYED;

		return Shadow::Utils::MemoryState::CONSTRUCTED;
	}
}
