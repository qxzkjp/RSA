#include "stdafx.h"
#include "mgf1.h"
#include "interfaces.h"
#include "memoryhelper.h"
#include "../SHA1/Sha1Class.h"

mgfPtr mgf1sha1 = [](charBuf::const_iterator begin, charBuf::const_iterator end, charBuf::iterator d_begin, size_t maskLen) {
	return MGF1<Sha1Class>(begin, end, d_begin, maskLen);
};
