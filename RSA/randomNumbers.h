#include "Buffer.h"

int getRandomBuffer(Buffer& buf, HCRYPTPROV hProvIn = NULL);
Buffer getRandomBuffer(size_t n, HCRYPTPROV hProv = 0);

mpz_class randomMpzClass(size_t n);

void randomMpz(size_t n, mpz_t m, HCRYPTPROV hProv = 0);

void initRandState(gmp_randstate_t state, HCRYPTPROV hProv);
