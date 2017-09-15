#include "stdafx.h"

#include "randomNumbers.h"
#include "CryptContext.h"

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