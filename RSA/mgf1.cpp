#include "stdafx.h"
#include "mgf1.h"
#include "interfaces.h"
#include "memoryhelper.h"
#include "../SHA1/Sha1Class.h"

//this function XORs its output with the output buffer, it does not directly write it
charBuf::iterator MGF1(hashPtr hash, charBuf::const_iterator begin, charBuf::const_iterator end, charBuf::iterator d_begin, size_t maskLen) {
	if (begin == end)
		return d_begin;
	size_t hLen = hash->length();
	//charBuf ret(maskLen);
	hash->reset();
	hash->addData(begin, end);
	if (maskLen > hLen << 32)
		throw 5; //throw random object and die if mask length too big
	size_t q = (maskLen + hLen - 1) / hLen; //ceiling of maskLen/hLen
	charBuf ctrvec(4);
	auto cbeg = ctrvec.begin();
	auto cend = ctrvec.end();
	charBuf hashout(hLen);
	auto bHash = hashout.begin();
	auto eHash = hashout.end();
	hashPtr hash2;
	//we fill up the output buffer in hlen-sized chunks; we can fit q-1 whole chunks in the buffer
	for (uint32_t counter = 0; counter < q - 1; ++counter) {
		hash2 = hash->clone();
		reverseMemcpy(&ctrvec[0], &counter, 4);//only works on little-endian
		hash2->addData(cbeg, cend);
		hash2->finalise(bHash);
		//		size_t check = it - ret.begin();
		d_begin = memxor(bHash, eHash, d_begin);
	}
	// now we do the final block, which might not be a whole block
	hash2 = hash->clone();
	size_t counter = q - 1;
	reverseMemcpy(&ctrvec[0], &counter, 4);//only works on little-endian
	hash2->addData(cbeg, cend);
	hash2->finalise(bHash);
	size_t r = (q * hLen) - maskLen;
	d_begin = memxor(bHash, eHash - r, d_begin);
	return d_begin;
}

mgfPtr mgf1sha1 = [](charBuf::const_iterator begin, charBuf::const_iterator end, charBuf::iterator d_begin, size_t maskLen) {
	return MGF1(std::make_shared<Sha1Class>(), begin, end, d_begin, maskLen);
};

charBuf MGF1(hashPtr hash, const charBuf& mgfSeed, size_t maskLen) {
	charBuf ret(maskLen);
	MGF1(hash, mgfSeed.cbegin(), mgfSeed.cend(), ret.begin(), maskLen);
	return ret;
}