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

class RsaEncryptor : virtual public Encryptor
{
public:
	RsaEncryptor(rsaPublicKey pk);
	virtual std::vector<char> encrypt(const std::vector<char>& M);
	virtual std::vector<char> exportKey();
	virtual void importKey(std::vector<char> buf);
protected:
	RsaEncryptor();
	mpz_class _N;
	mpz_class _e;
};

class RsaDecryptor : public RsaEncryptor, virtual public Decryptor
{
public:
	RsaDecryptor(size_t sz = 2048);
	virtual std::vector<char> decrypt(const std::vector<char>& C);
	virtual void generateKey(size_t sz);
	virtual std::vector<char> exportKey();
	virtual void importKey(std::vector<char> buf);
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

