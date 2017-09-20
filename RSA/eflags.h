#pragma once

#if defined( _MSC_VER )
#include <intrin.h>
#endif

#ifdef __GNUC__
#if __x86_64__ || __ppc64__
#define GNU64
#else
#define GNU32
#endif
#endif
//borrowed from stackoverflow https://stackoverflow.com/a/13764376
//query_intel_x86_eflags(0x801) gives carry and overflow flags
inline size_t query_intel_x86_eflags(const size_t query_bit_mask)
{
#if defined( _MSC_VER )
	return __readeflags() & query_bit_mask;
#elif defined( GNU64 )
	// this code will work only on 64-bit GNU-C machines;
	// Tested and does NOT work with Intel C++ 10.1!
	size_t eflags;
	__asm__ __volatile__(
		"pushfq \n\t"
		"pop %%rax\n\t"
		"movq %%rax, %0\n\t"
		:"=r"(eflags)
		:
		: "%rax"
	);
	return eflags & query_bit_mask;
#else
#pragma message("No inline assembly will work with this compiler!")
	return 0;
#endif
}
