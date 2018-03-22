#include <vector>
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

int getRandomBuffer(std::vector<char>& buf, HCRYPTPROV hProvIn = NULL);
std::vector<char> getRandomBuffer(size_t n, HCRYPTPROV hProvIn = NULL);
int getRandomBuffer(std::vector<char>::iterator begin, std::vector<char>::iterator end, HCRYPTPROV hProvIn = NULL);

mpz_class randomMpzClass(size_t n);

void randomMpz(size_t n, mpz_t m, HCRYPTPROV hProv = 0);

void initRandState(gmp_randstate_t state, HCRYPTPROV hProv);
