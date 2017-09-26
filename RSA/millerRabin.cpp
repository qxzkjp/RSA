#include "stdafx.h"

#include "randomNumbers.h"
#include "mpzConvert.h"

mpz_class smallPrimeProduct = 3LL * 5 * 7 * 11 * 13 * 17 * 19 * 23 * 29 * 31 * 37 * 41 * 43 * 47;

void millerRabinDecomp(const mpz_class& n, mpz_class& d, mp_bitcnt_t& s) {
	s = 0;
	//n shouldn't be negative or zero, but we return 0,0 if it is
	if (n <= 0) {
		d = 0;
	}
	else {
		d = n - 1;
		for (int i = 0; i < d.get_mpz_t()->_mp_size; ++i) {
			mp_limb_t tmp = d.get_mpz_t()->_mp_d[i];
			if (tmp == 0) {
				s += GMP_LIMB_BITS;
			}
			else {
				while (tmp % 2 == 0) {
					++s;
					tmp >>= 1;
				}
				break;
			}
		}
		mpz_fdiv_q_2exp(d.get_mpz_t(), d.get_mpz_t(), s);
	}
}

//efficiently generates a uniform random integer between 0 and limit-1
mpz_class randRangeMpz(const mpz_class& limit) {
	size_t u = mpz_sizeinbase(limit.get_mpz_t(), 2);
	//add bits onto u if not whole bytes to make it whole; add on extra byte if it is, to ensure 2^u bigger than limit
	u = u + (8 - (u % 8));
	if (u <= 0) //if the number is too large (like, waaaaaaaay large) we're in a no-win situation, crash
		throw(5);
	mpz_class t = 1;
	mpz_mul_2exp(t.get_mpz_t(), t.get_mpz_t(), u);//t=2^u
												  //take remainder off t, so it's evenly divisible by limit
	mpz_class r;
	mpz_fdiv_r(r.get_mpz_t(), t.get_mpz_t(), limit.get_mpz_t());
	t -= r;
	mpz_class x;
	do {
		x = randomMpzClass(u / 8); //function takes size in bytes
	} while (x > t);
	return x % limit;
}

bool millerRabin(const mpz_class& n, size_t k) {
	//thow out some easy cases
	if (n <= 1)
		return false;
	mpz_class d;
	mp_bitcnt_t s;
	millerRabinDecomp(n, d, s);
	for (size_t i = 0; i < k; ++i) {
		mpz_class a = 4; randRangeMpz(n - 1);//globalStateClass.get_z_range(n - 1);
											 //a^d mod n
		mpz_class x;
		mpz_powm(x.get_mpz_t(), a.get_mpz_t(), d.get_mpz_t(), n.get_mpz_t());
		if (x == 1 || x == n - 1)
			continue;
		for (size_t j = 0; j < s - 1; ++j) {
			x = (x*x) % n; //squaring is basic, no need for fancy-pants algos
			if (x == 1)
				return false;
			if (x == n - 1)
				continue;
		}
		return false;
	}
	return true;
	return false;
}

bool likelyPrime(const mpz_class& n) {
	//quick check for divisibility by the first few primes
	mpz_class r = n%smallPrimeProduct;
	mpz_class gcd;
	mpz_gcd(gcd.get_mpz_t(), r.get_mpz_t(), smallPrimeProduct.get_mpz_t());
	if (gcd != 1)
		return false;
	//if it passes trial division, do miller-rabin
	size_t rounds = (mpz_sizeinbase(n.get_mpz_t(), 2) + 1) / 2; //ceiling of half the bit size is a good number of rounds
	return millerRabin(n, rounds);
	return false;
}