#include "Buffer.h"
#include <vector>

int getRandomBuffer(std::vector<char>& buf, HCRYPTPROV hProvIn = NULL);
std::vector<char> getRandomBuffer(size_t n, HCRYPTPROV hProvIn = NULL);
int getRandomBuffer(std::vector<char>::iterator begin, std::vector<char>::iterator end, HCRYPTPROV hProvIn = NULL);

mpz_class randomMpzClass(size_t n);

void randomMpz(size_t n, mpz_t m, HCRYPTPROV hProv = 0);

void initRandState(gmp_randstate_t state, HCRYPTPROV hProv);
