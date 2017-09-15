#pragma once
#include "Buffer.h"
#include "interfaces.h"
#include <mpir.h>
#include <mpirxx.h>
#include "Buffer.h"

bool oldLikelyPrime(mpz_class n);

mpz_class getBigPrime(size_t bits);

struct rsaPublicKey
{
	mpz_class N;
	mpz_class e;
};

class RsaEncryptor : public AsymmetricEncryptor
{
public:
	RsaEncryptor(rsaPublicKey pk);
	virtual std::vector<char> encrypt(const Buffer& M);
protected:
	RsaEncryptor();
	mpz_class _N;
	mpz_class _e;
};

class RsaDecryptor : public RsaEncryptor, public AsymmetricDecryptor
{
public:
	RsaDecryptor(size_t sz = 2048);
	//virtual std::vector<char> encrypt(const Buffer& M);
	virtual std::vector<char> decrypt(const Buffer& C);
private:
	mpz_class _p;
	mpz_class _q;
	mpz_class _N;
	mpz_class _e;
	mpz_class _d;
	mpz_class _dp;
	mpz_class _dq;
	mpz_class _qinv;
};

