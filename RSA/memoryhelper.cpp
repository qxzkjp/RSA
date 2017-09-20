#include "stdafx.h"
#include "memoryhelper.h"

void reverseMemcpy(void* dst, void* src, size_t cnt) {
	char* d = (char*)dst;
	char* s = (char*)src;
	for (size_t i = 0; i < cnt; ++i)
		d[cnt - i - 1] = s[i];
}