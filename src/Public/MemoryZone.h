#pragma once
#include "Kerbecs.h"

namespace Kerbecs::MemoryZone {
	constexpr size_t MEMORY_ZONE_ADDRESS = 0x0000100000000000; //Preferred by Kerbecs
	constexpr size_t POISON_NON_HEAP = 0xfa;
	constexpr size_t POISON_HEAP = 0xfb;
	constexpr size_t UNPOISONED_NON_HEAP = 0x0a;
	constexpr size_t UNPOISONED_HEAP = 0x0b;
	constexpr size_t REDZONE = 0xfe;
	constexpr size_t TOMBSTONE = 0xdd;
	constexpr size_t GUARD_CANARY = 0xdead;

	struct KERBECS KerbecsMemoryZone final {
		void* m_MemoryZone;
		void* m_ShadowZone;
		void* m_GlobalZone;

		bool m_Initialized;

		[[nodiscard]] bool init();
	};

	inline KERBECS KerbecsMemoryZone& instance() {
		static KerbecsMemoryZone instance;
		return instance;
	}
}
