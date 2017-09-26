#pragma once
template<class InputIt, class OutputIt>
OutputIt memxor(InputIt first, InputIt last, OutputIt d_first) {
	size_t sz = last - first;
	OutputIt ret = d_first + sz;
	if (sz <= 0)
		return d_first;
	sz *= sizeof(*first);
	char* bInPtr = (char*)&first[0];
	char* bOutPtr = (char*)&d_first[0];
	size_t chunkSz = sizeof(uint64_t);
	uintptr_t r = (uintptr_t)bInPtr % chunkSz;
	if (r != 0) {
		for (uintptr_t i = 0; i < chunkSz - r; ++i) {
			*bOutPtr++ ^= *bInPtr++;
		}
		sz -= chunkSz - r;
	}
	uint64_t* qInPtr = (uint64_t*)bInPtr;
	uint64_t* qOutPtr = (uint64_t*)bOutPtr;
	for (size_t i = 0; i < sz / chunkSz; ++i)
		*qOutPtr++ ^= *qInPtr++;
	sz = sz % 8;
	bInPtr = (char*)qInPtr;
	bOutPtr = (char*)qOutPtr;
	for (size_t i = 0; i < sz; ++i)
		*bOutPtr++ ^= *bInPtr++;
	return ret;
}

inline void reverseMemcpy(void* dst, void* src, size_t cnt) {
	char* d = (char*)dst;
	char* s = (char*)src;
	for (size_t i = 0; i < cnt; ++i)
		d[cnt - i - 1] = s[i];
}
