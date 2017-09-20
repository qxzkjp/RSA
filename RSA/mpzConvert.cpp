#include "stdafx.h"
#include "mpzConvert.h"
#include <algorithm>

//little-endian
mpz_class byteToMpzClass(BYTE* buf, size_t n) {
	mpz_class p;
	mpz_import(p.get_mpz_t(), n, -1, 1, 0, 0, (void*)buf);
	return p;
}

//little-endian word order; processor-default byte order
mpz_class int64ToMpzClass(uint64_t* buf, size_t n) {
	mpz_class p;
	mpz_import(p.get_mpz_t(), n, -1, 8, 0, 0, (void*)buf);
	return p;
}

//little-endian word order; processor-default byte order
mpz_class limbToMpzClass(mp_limb_t *buf, size_t n) {
	mpz_class p;
	mpz_import(p.get_mpz_t(), n, -1, SIZEOF_MP_LIMB_T, 0, 0, (void*)buf);
	return p;
}

//little-endian
//don't use this
void byteToMpz(BYTE* buf, size_t n, mpz_t m) {
	mpz_class p;
	mpz_import(m, n, -1, 1, -1, 0, (void*)buf);
}

//these two functions are BIG-ENDIAN, to comply with RSA spec
std::vector<char> mpzClassToVector(mpz_class n, size_t sz) {
	size_t filledBytes = (mpz_sizeinbase(n.get_mpz_t(), 2) + 7) >> 3;
	size_t numBytes = std::max((mpz_sizeinbase(n.get_mpz_t(), 2) + 7) >> 3, sz);
	size_t pad = 0;
	//we zero-pad the number to get sz bytes, if neccessary
	if (filledBytes > sz)
		sz = filledBytes;
	else
		pad = sz - filledBytes;
	std::vector<char> ret(numBytes);
	mpz_export(&ret[pad], NULL, 1, 1, 0, 0, n.get_mpz_t());
	return ret;
}

mpz_class vectorToMpzClass(std::vector<char> v) {
	mpz_class p = 0;
	if(v.size() > 0)
		mpz_import(p.get_mpz_t(), v.size(), 1, 1, 0, 0, &v[0]);
	return p;
}