#pragma once
#include "Interfaces.h"
#include "memoryhelper.h"

//this function XORs its output with the output buffer, it does not directly write it
template<class Hash>
charBuf::iterator MGF1(charBuf::const_iterator begin, charBuf::const_iterator end, charBuf::iterator d_begin, size_t maskLen) {
	if (begin == end)
		return d_begin;
	
	Hash hash;
	size_t hLen = hash.length();
	if (maskLen > hLen << 32)
		throw 5; //throw random object and die if mask length too big
	size_t q = (maskLen + hLen - 1) / hLen; //ceiling of maskLen/hLen
	charBuf ctrvec(4);
	auto cbeg = ctrvec.begin();
	auto cend = ctrvec.end();
	charBuf hashout(hLen);
	auto bHash = hashout.begin();
	auto eHash = hashout.end();
	//we fill up the output buffer in hlen-sized chunks; we can fit q-1 whole chunks in the buffer
	for (uint32_t counter = 0; counter < q - 1; ++counter) {
		//every block begins with the seed
		hash.reset();
		hash.addData(begin, end);
		//turn 32-bit counter into a big-endian 4-byte buffer, then add it to the hash state
		reverseMemcpy(&ctrvec[0], &counter, 4);//only works on little-endian
		hash.addData(cbeg, cend);
		//that's it, so finalise the hash and xor the output with the next n bytes of the buffer
		hash.finalise(bHash);
		//		size_t check = it - ret.begin();
		d_begin = memxor(bHash, eHash, d_begin);
	}
	// now we do the final block, which might not be a whole block
	hash.reset();
	hash.addData(begin, end);
	size_t counter = q - 1;
	reverseMemcpy(&ctrvec[0], &counter, 4);//only works on little-endian
	hash.addData(cbeg, cend);
	hash.finalise(bHash);
	size_t r = (q * hLen) - maskLen;
	d_begin = memxor(bHash, eHash - r, d_begin);
	return d_begin;
}

extern mgfPtr mgf1sha1;

//this function returns a charBuf containing the mask
template<class Hash>
charBuf MGF1(const charBuf& mgfSeed, size_t maskLen) {
	charBuf ret(maskLen);
	MGF1<Hash>(mgfSeed.cbegin(), mgfSeed.cend(), ret.begin(), maskLen);
	return ret;
}

template<class Hash>
class MGF1_class {
public:
	MGF1_class(charBuf seed) : _seed(seed) {
		
	}
	MGF1_class() : _seed(charBuf()) {

	}
	void reSeed(charBuf seed) {
		_seed = seed;
	}
	charBuf getMask(size_t length) {
		return MGF1<Hash>(_seed, length);
	}
	charBuf::iterator xorMask(charBuf::iterator buffer, size_t length) {
		return MGF1<Hash>(_seed.begin(), _seed.end(), buffer, length);
	}
	charBuf::iterator xorMaskWithSeed(charBuf::iterator seedBegin, charBuf::iterator seedEnd, charBuf::iterator buffer, size_t length) {
		return MGF1<Hash>(seedBegin, seedEnd, buffer, length);
	}
private:
	charBuf _seed;
};