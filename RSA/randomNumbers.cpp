#include "stdafx.h"

#include "randomNumbers.h"
#include "mpzConvert.h"

CryptContext::CryptContext() {
	if (!CryptAcquireContext(
		&_h,
		NULL,
		NULL,
		PROV_RSA_FULL,
		0)) {
		std::cerr << "CryptContext: could not acquire context" << std::endl;
		throw(5); //throw random object to kill execution
	}
	initRandState(_s, _h);
}

CryptContext::~CryptContext() {
	if (_h)
		if (!CryptReleaseContext(_h, 0))
			std::cerr << "~CryptContext: could not release context" << std::endl;
	gmp_randclear(_s);
}

HCRYPTPROV& CryptContext::handle() {
	return _h;
}
gmp_randstate_t& CryptContext::gmpState() {
	return _s;
}

CryptContext globalContext;

int getRandomBuffer(std::vector<char>& v, HCRYPTPROV hProvIn) {
	if (v.size() == 0)
		return 0;
	if (v.size() > ULONG_MAX) {
		std::cerr << "getRandomBuffer: buffer size too large" << std::endl;
		return 1;
	}
	//this actually should still work in 32-bit, q will always be 0
	uint32_t q = v.size() >> 32;
	uint32_t r = v.size() & 0xFFFFFFFF;
	HCRYPTPROV hProv;
	if (hProvIn)
		hProv = hProvIn;
	else
		hProv = globalContext.handle();
	for (size_t i = 0; i < q; ++i) {
		//this if-statement fills the buffer!
		if (!CryptGenRandom(hProv, ULONG_MAX, (BYTE*)&v[i*ULONG_MAX])) {
			std::cerr << "getRandomBuffer: could not fill buffer" << std::endl;
			return 1;
		}
	}
	//this if-statement fills the buffer!
	if (!CryptGenRandom(hProv, r, (BYTE*)&v[(size_t)q * ULONG_MAX])) {
		std::cerr << "getRandomBuffer: could not fill buffer" << std::endl;
		return 1;
	}
	return 0;
}

int getRandomBuffer(std::vector<char>::iterator begin, std::vector<char>::iterator end, HCRYPTPROV hProvIn) {
	if (begin == end)
		return 0;
	size_t sz = end - begin;
	/*if (v.size() > ULONG_MAX) {
		std::cerr << "getRandomBuffer: buffer size too large" << std::endl;
		return 1;
	}*/
	//this actually should still work in 32-bit, q will always be 0
	uint32_t q = sz >> 32;
	uint32_t r = sz & 0xFFFFFFFF;
	HCRYPTPROV hProv;
	if (hProvIn)
		hProv = hProvIn;
	else
		hProv = globalContext.handle();
	for (size_t i = 0; i < q; ++i) {
		//this if-statement fills the buffer!
		if (!CryptGenRandom(hProv, ULONG_MAX, (BYTE*)&begin[i*ULONG_MAX])) {
			std::cerr << "getRandomBuffer: could not fill buffer" << std::endl;
			return 1;
		}
	}
	//this if-statement fills the buffer!
	if (!CryptGenRandom(hProv, r, (BYTE*)&begin[(size_t)q * ULONG_MAX])) {
		std::cerr << "getRandomBuffer: could not fill buffer" << std::endl;
		return 1;
	}
	return 0;
}

std::vector<char> getRandomBuffer(size_t n, HCRYPTPROV hProv ) {
	std::vector<char> buf(n);
	if (getRandomBuffer(buf, hProv) != 0) {
		buf = std::vector<char>(0);
	}
	return buf;
}

mpz_class randomMpzClass(size_t n) {
	std::vector<char> buf(n);
	getRandomBuffer(buf);
	mpz_class ret = vectorToMpzClass(buf);
	return ret;
}

void randomMpz(size_t n, mpz_t m, HCRYPTPROV hProv ) {
	std::vector<char> buf = getRandomBuffer(n, hProv);
	if (buf.size() == 0) {
		std::cerr << "randomMpz: could not fill buffer" << std::endl;
		return;
	}
	byteToMpz((uint8_t*)&buf[0], n, m);
}

void initRandState(gmp_randstate_t state, HCRYPTPROV hProv) {
	mpz_t n;
	mpz_init(n);
	randomMpz(8192, n, hProv); // big seed
	gmp_randinit_mt(state);
	gmp_randseed(state, n);
	mpz_clear(n);
}