#include "stdafx.h"

#include "CryptContext.h"
#include "randomNumbers.h"
#include "mpzConvert.h"

int getRandomBuffer(Buffer& buf, HCRYPTPROV hProvIn) {
	if (buf.size() > INT_MAX) {
		std::cerr << "getRandomBuffer: buffer size too large" << std::endl;
		return 1;
	}
	HCRYPTPROV hProv;
	if (hProvIn)
		hProv = hProvIn;
	else
		hProv = globalContext.handle();

	//we're ok to convert n to DWORD, as we checked it against INT_MAX
	//this if-statement fills the buffer!
	if (!CryptGenRandom(hProv, (DWORD)buf.size(), buf.raw())) {
		std::cerr << "getRandomBuffer: could not fill buffer" << std::endl;
		return 1;
	}
	return 0;
}

Buffer getRandomBuffer(size_t n, HCRYPTPROV hProv ) {
	if (n > INT_MAX || n <= 0) {
		std::cerr << "getRandomBuffer: buffer size too large or non-positive" << std::endl;
		return Buffer(0);
	}
	Buffer buf(n);
	if (getRandomBuffer(buf, hProv) != 0) {
		buf = Buffer(0);
	}
	return buf;
}

mpz_class randomMpzClass(size_t n) {
	Buffer buf(n);
	getRandomBuffer(buf);
	mpz_class ret = bufferToMpzClass(buf);
	return ret;
}

void randomMpz(size_t n, mpz_t m, HCRYPTPROV hProv ) {
	Buffer buf = getRandomBuffer(n, hProv);
	if (buf.size() == 0) {
		std::cerr << "randomMpz: could not fill buffer" << std::endl;
		return;
	}
	byteToMpz(buf.raw(), n, m);
}

void initRandState(gmp_randstate_t state, HCRYPTPROV hProv) {
	mpz_t n;
	mpz_init(n);
	randomMpz(8192, n, hProv); // big seed
	gmp_randinit_mt(state);
	gmp_randseed(state, n);
	mpz_clear(n);
}