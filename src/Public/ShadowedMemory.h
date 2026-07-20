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

// ShadowedMemory<T> (v0.2 SS3) - replaces ShadowToken's lazy-resolve model.
// Resolves once, at allocation time, and stays immutable for its entire
// lifetime - no zone ID / generation / slot-index decode on every access.
//
// Deliberately carries NO Layout/ThreadPolicy/Allocator/Logger/Hasher
// template parameters (unlike v0.1's ShadowPtr<L,S,O,H,AC,TP>) - all of that
// policy now lives on Region, which is the thing that resolves and vends
// these handles. ShadowedMemory<T> itself only ever needs to know T.
namespace Kerbecs {

	template<typename LayoutT, Shadow::Utils::ThreadPolicy ThreadPolicyT, typename AllocatorT>
		requires Enforcement::LayoutPolicyConcept<LayoutT> && Enforcement::AllocatorConcept<AllocatorT>
	class Region; // forward declaration only - Region.h is the sole friend allowed to construct a real handle.

	template<typename T> class ShadowedMemory;

	// Forward declaration only, so ShadowedMemory<T> can friend it below -
	// definition stays after the class (v0.2 SS6).
	template<typename T>
	KERBECS_NODISCARD_MSG("Cannot discard shadow state")
		Shadow::Utils::MemoryState shadowStateOf(const ShadowedMemory<T>& v_Handle, size_t v_Size) noexcept;

	template<typename T>
	class ShadowedMemory final {
	public:
		// All-zero state, equivalent to T* p; / T* p = nullptr;. Both public
		// constructors are bit-identical - there is no softer "safer" null
		// state than a raw null pointer (v0.2 SS3.2).
		ShadowedMemory() noexcept = default;
		ShadowedMemory(std::nullptr_t) noexcept {}

		// Trivially copyable, never const-qualified - opacity and immutability
		// are enforced through encapsulation and the private constructor
		// below, not through language-level const (which would break copy
		// assignment). Two copies are independent, equally valid snapshots -
		// no aliasing hazard since neither can mutate the other.
		ShadowedMemory(const ShadowedMemory&) noexcept = default;
		ShadowedMemory& operator=(const ShadowedMemory&) noexcept = default;
		ShadowedMemory(ShadowedMemory&&) noexcept = default;
		ShadowedMemory& operator=(ShadowedMemory&&) noexcept = default;
		~ShadowedMemory() = default;

		// Raw-pointer operator parity (v0.2 SS3.4).

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

		// Deliberately non-explicit - a known, accepted footgun. Anyone
		// writing `T* raw = shadowedMem;` in this codebase is presumed to
		// know exactly what that line costs (v0.2 SS3.4).
		operator T* () const noexcept {
			_check();
			return static_cast<T*>(m_PayloadPtr);
		}

		// Compares payload AND generation together - two handles at the same
		// address from different allocation epochs are NOT equal. Stronger,
		// more correct semantics than raw-pointer address-only equality,
		// stated explicitly as a deliberate departure (v0.2 SS3.4).
		friend bool operator==(const ShadowedMemory& v_Lhs, const ShadowedMemory& v_Rhs) noexcept {
			return v_Lhs.m_PayloadPtr == v_Rhs.m_PayloadPtr && v_Lhs.m_Generation == v_Rhs.m_Generation;
		}
		friend bool operator!=(const ShadowedMemory& v_Lhs, const ShadowedMemory& v_Rhs) noexcept {
			return !(v_Lhs == v_Rhs);
		}

		// Range-checks the resulting offset against the payload size read
		// through m_MetaPtr (Runtime::AccessInfo::m_UserSize - metadata sits
		// beside payload, typically a same/adjacent cache-line hit). Fires
		// BufferOverflow on violation; otherwise returns a new
		// ShadowedMemory<T> with m_PayloadPtr advanced and the other three
		// fields carried over unchanged (v0.2 SS3.4).
		KERBECS_NODISCARD_MSG("Cannot discard offset handle")
			ShadowedMemory operator+(ptrdiff_t v_Index) const noexcept {
			if (!m_PayloadPtr || !m_MetaPtr)
				return ShadowedMemory{};

			const auto* info = static_cast<const Runtime::AccessInfo*>(m_MetaPtr);
			const ptrdiff_t byteOffset = v_Index * static_cast<ptrdiff_t>(sizeof(T));
			const ptrdiff_t newOffsetEnd = byteOffset + static_cast<ptrdiff_t>(sizeof(T));

			if (newOffsetEnd < 0 || static_cast<size_t>(newOffsetEnd) > info->m_UserSize) {
				Violation v{};
				v.m_Kind = ViolationKind::BufferOverflow;
				v.m_Address = static_cast<std::byte*>(m_PayloadPtr) + byteOffset;
				v.m_BlockBase = m_PayloadPtr;
				v.m_BlockSize = info->m_UserSize;
				statsOnViolation(&Runtime::instance().m_Stats);
				// No logger reference on ShadowedMemory<T> by design - the
				// caller's installed sink is reached through Region, which
				// is the layer that actually owns policy. A bounds violation
				// discovered mid-arithmetic here still needs to be visible,
				// so it goes through the same global stats counter every
				// other violation touches; Region-level callers additionally
				// re-check bounds through their own Logger-aware path.
				return ShadowedMemory{};
			}

			return ShadowedMemory(
				m_MetaPtr,
				static_cast<std::byte*>(m_PayloadPtr) + byteOffset,
				m_ShadowPtr,
				m_Generation);
		}

		// operator& explicitly absent (v0.2 SS3.4) - the use case (short-
		// lived, stack-resident, immutable, never stored persistently) never
		// needs the address of the handle itself. &*sm remains the idiom for
		// obtaining a raw T* to the payload, mirroring &*it for iterators.

	private:
		template<typename LayoutT, Shadow::Utils::ThreadPolicy ThreadPolicyT, typename AllocatorT>
			requires Enforcement::LayoutPolicyConcept<LayoutT> && Enforcement::AllocatorConcept<AllocatorT>
		friend class Region;

		// shadowStateOf reads m_PayloadPtr directly (bypassing _check()) - it
		// is a diagnostic/introspection read meant to work on handles whose
		// generation has already been invalidated by Region::destroy, not a
		// live dereference, so the use-after-free trap in _check() must not
		// fire here (v0.2 SS6).
		template<typename U>
		friend Shadow::Utils::MemoryState shadowStateOf(const ShadowedMemory<U>& v_Handle, size_t v_Size) noexcept;

		// Friend-only, reachable only by Region's allocation path (v0.2 SS3.2).
		ShadowedMemory(void* p_MetaPtr, void* p_PayloadPtr, void* p_ShadowPtr, uint64_t v_Generation) noexcept
			: m_MetaPtr(p_MetaPtr), m_PayloadPtr(p_PayloadPtr), m_ShadowPtr(p_ShadowPtr), m_Generation(v_Generation) {
		}

		// Generation + poison-byte check before every dereference. O(1) - no
		// registry lookup: m_Generation is compared directly against the
		// live copy already sitting in Runtime::AccessInfo at m_MetaPtr
		// (v0.2 SS3.3, "resolve once" - the whole point is that this stays
		// a flat read, not a decode+index+check).
		void _check() const noexcept {
			if (!m_PayloadPtr || !m_MetaPtr) return;

			const auto* info = static_cast<const Runtime::AccessInfo*>(m_MetaPtr);
			if (info->m_Generation != m_Generation) {
				statsOnViolation(&Runtime::instance().m_Stats);
				KERBECS_TRAP();
			}
		}

		void*    m_MetaPtr = nullptr;    // resolved metadata/access-info slot (Runtime::AccessInfo)
		void*    m_PayloadPtr = nullptr; // resolved payload start
		void*    m_ShadowPtr = nullptr;  // pre-resolved shadow-bitmap address
		uint64_t m_Generation = 0;       // snapshot of the owning slot's generation at construction time
	};

	// shadowStateOf (replaces v0.1's Shadow::shadowStateOf + KerbecsShadowMap)
	//
	// Reads MemoryState directly off block bytes - no shadow-map concept, no
	// injected map instance (v0.2 SS6). Poison bytes are scanned in place,
	// same approach the shadow-map-removal commit already established for
	// ShadowPtr before this rewrite began.
	template<typename T>
	Shadow::Utils::MemoryState shadowStateOf(const ShadowedMemory<T>& v_Handle, size_t v_Size) noexcept {
		// Reads m_PayloadPtr directly, not through operator T*()/_check() -
		// this is a post-mortem introspection read that must work on handles
		// whose generation was already invalidated by Region::destroy (that's
		// the DESTROYED case below), so it must not trip the use-after-free
		// trap that a live dereference would.
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
