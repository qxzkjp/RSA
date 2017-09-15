#pragma once

class CryptContext
{
public:
	CryptContext();
	~CryptContext();
	HCRYPTPROV& handle();
	gmp_randstate_t& gmpState();
private:
	HCRYPTPROV _h;
	gmp_randstate_t _s;
};

extern CryptContext globalContext;