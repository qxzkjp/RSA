#include "stdafx.h"
#include "RsaDecryptor.h"
#include "randomNumbers.h"
#include "mpzConvert.h"
#include "CryptContext.h"

bool oldLikelyPrime(mpz_class n) {
	return mpz_likely_prime_p(n.get_mpz_t(), globalContext.gmpState(), 0);
}

mpz_class getBigPrime(size_t bits) {
	mpz_class p = 0;
	size_t sz = (bits + 7) / 8; //ceiling of bits/8, so prime may be larger than needed
	Buffer buf(sz);
	while (!oldLikelyPrime(p)) {
		getRandomBuffer(buf);
		//if we have a appropriately-sized buffer, we feed in data a limb at a time, otherwise a byte at a time
		if (sz % SIZEOF_MP_LIMB_T == 0) {
			size_t bigSz = sz / SIZEOF_MP_LIMB_T;
			mp_limb_t* bigBuf = (mp_limb_t*)buf.raw();
			bigBuf[bigSz - 1] |= 0xC0LL << (8 * (SIZEOF_MP_LIMB_T - 1));		//set two high bits, to ensure number is large enough
			bigBuf[0] |= 0x01;													//set low bit, to ensure number is odd
			p = limbToMpzClass(bigBuf, bigSz);
		}
		else {
			buf[sz - 1] |= 0xC0;	//set two high bits, to ensure number is large enough
			buf[0] |= 0x01;			//set low bit, to ensure number is odd
			p = bufferToMpzClass(buf);
		}
	}
	return p;
}

RsaEncryptor::RsaEncryptor(rsaPublicKey pk) : _N(pk.N), _e(pk.e) {
	if (_N == 0 || _e > _N)
		throw 5;//throw random obbject to crash if invalid key is passed
}

// only used to make derived classes, can't be publically called so we can't have a blank instance
RsaEncryptor::RsaEncryptor() {
}

std::vector<char> RsaEncryptor::encrypt(const Buffer& M)
{
	mpz_class m = bufferToMpzClass(M);
	mpz_class c;
	mpz_powm(c.get_mpz_t(), m.get_mpz_t(), _e.get_mpz_t(), _N.get_mpz_t());
	std::vector<char> C = mpzClassToVector(c);
	return C;
}

RsaDecryptor::RsaDecryptor(size_t sz)
{
	_p = getBigPrime(sz / 2);
	_q = getBigPrime(sz / 2);
	_N = _p*_q;
	_e = 65537;
	mpz_class lambda;
	mpz_class gcd;
	--_p;
	--_q;
	mpz_lcm(lambda.get_mpz_t(), _p.get_mpz_t(), _q.get_mpz_t());
	mpz_gcdext(gcd.get_mpz_t(), _d.get_mpz_t(), NULL, _e.get_mpz_t(), lambda.get_mpz_t()); //e=d^-1 mod lambda
	_dp = _d % _p; // d mod p-1
	_dq = _d % _q; // d mod q-1
	++_p;
	++_q;
	mpz_gcdext(gcd.get_mpz_t(), _qinv.get_mpz_t(), NULL, _q.get_mpz_t(), _p.get_mpz_t()); //q^-1 mod p
}

std::vector<char> RsaDecryptor::decrypt(const Buffer& C)
{
	mpz_class c = bufferToMpzClass(C);
	mpz_class m, m1, m2, m3, h;
	mpz_powm(m1.get_mpz_t(), c.get_mpz_t(), _dp.get_mpz_t(), _p.get_mpz_t());
	mpz_powm(m2.get_mpz_t(), c.get_mpz_t(), _dq.get_mpz_t(), _q.get_mpz_t());
	//m3 is a dummy, to prevent timing attacks. let's hope the compiler does not optimise it away
	m3 = m1;
	if (m1 < m2) {
		m1 = m1 + _p;
	}
	else {
		m3 = m3 + _p;
	}
	h = (_qinv*(m1 - m2)) % _p;
	m = m2 + h*_q;
	std::vector<char> M = mpzClassToVector(m);
	return M;
}
