#include "stdafx.h"
#include "mpzConvert.h"

mpz_class byteToMpzClass(BYTE* buf, size_t n) {
	mpz_class p;
	mpz_import(p.get_mpz_t(), n, -1, 1, -1, 0, (void*)buf);
	return p;
}

mpz_class int64ToMpzClass(uint64_t* buf, size_t n) {
	mpz_class p;
	mpz_import(p.get_mpz_t(), n, -1, 8, 0, 0, (void*)buf);
	return p;
}

mpz_class limbToMpzClass(mp_limb_t *buf, size_t n) {
	mpz_class p;
	mpz_import(p.get_mpz_t(), n, -1, SIZEOF_MP_LIMB_T, 0, 0, (void*)buf);
	return p;
}

void byteToMpz(BYTE* buf, size_t n, mpz_t m) {
	mpz_class p;
	mpz_import(m, n, -1, 1, -1, 0, (void*)buf);
}

std::vector<char> mpzClassToVector(mpz_class n) {
	size_t numBytes = (mpz_sizeinbase(n.get_mpz_t(), 2) + 7) >> 3;
	std::vector<char> ret(numBytes);
	mpz_export(&ret[0], NULL, 1, 1, -1, 0, n.get_mpz_t());
	return ret;
}