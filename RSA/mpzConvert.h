#pragma once

#include <windows.h>
#include <mpirxx.h>
#include <vector>

mpz_class byteToMpzClass(BYTE* buf, size_t n);
mpz_class int64ToMpzClass(uint64_t* buf, size_t n);
mpz_class limbToMpzClass(mp_limb_t *buf, size_t n);
void byteToMpz(BYTE* buf, size_t n, mpz_t m);

std::vector<char> mpzClassToVector(mpz_class n);
mpz_class vectorToMpzClass(std::vector<char> v);
