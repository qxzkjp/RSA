#pragma once
#include "interfaces.h"
#include <mpir.h>
#include <mpirxx.h>
#include "mgf1.h"
#include "../SHA1/Sha1Class.h"

bool oldLikelyPrime(mpz_class n);

mpz_class getBigPrime(size_t bits);

struct rsaPublicKey
{
	mpz_class N;
	mpz_class e;
};

struct rsaPrivateKey
{
	mpz_class N;
	mpz_class e;
	mpz_class d;
	mpz_class p;
	mpz_class q;
	mpz_class dp;
	mpz_class dq;
	mpz_class qinv;
};

class RsaEncryptor : virtual public Encryptor
{
public:
	RsaEncryptor(rsaPublicKey pk);
	virtual std::vector<char> encrypt(const std::vector<char>& M);
	virtual std::vector<char> exportKey();
	virtual void importKey(std::vector<char> buf);
	size_t keySize();
protected:
	mpz_class _N;
	mpz_class _e;
	size_t _ksz;
};

class RsaDecryptor : virtual public RsaEncryptor, virtual public Decryptor
{
public:
	RsaDecryptor(rsaPrivateKey);
	virtual std::vector<char> decrypt(const std::vector<char>& C);
	virtual void generateKey(size_t sz);
	virtual std::vector<char> exportKey();
	virtual void importKey(std::vector<char> buf);
private:
	mpz_class _p;
	mpz_class _q;
	mpz_class _d;
	mpz_class _dp;
	mpz_class _dq;
	mpz_class _qinv;
};

class RsaOaepEncryptor : virtual protected RsaEncryptor, virtual public TaggedEncryptor {
public: 
	RsaOaepEncryptor(rsaPublicKey pk, mgfPtr mgf = mgf1sha1, hashPtr hash=std::make_shared<Sha1Class>());
	virtual std::vector<char> encrypt(const std::vector<char>& M, const std::vector<char>& L);
	virtual std::vector<char> encrypt(const std::vector<char>& M) { return encrypt(M, charBuf(0)); };
	virtual std::vector<char> exportKey() { return charBuf(0); };
	virtual void importKey(std::vector<char> buf) {};
protected:
	mgfPtr _mgf;
	hashPtr _hash;
	size_t _hLen;
};

class RsaOaepDecryptor : protected RsaDecryptor, public RsaOaepEncryptor, virtual public TaggedDecryptor {
public:
	RsaOaepDecryptor(rsaPrivateKey pk, mgfPtr mgf = mgf1sha1, hashPtr hash = std::make_shared<Sha1Class>());
	virtual std::vector<char> encrypt(const std::vector<char>& M, const std::vector<char>& L) { return RsaOaepEncryptor::encrypt(M, L); };
	virtual std::vector<char> encrypt(const std::vector<char>& M) { return RsaOaepEncryptor::encrypt(M); };
	virtual std::vector<char> decrypt(const std::vector<char>& C, const std::vector<char>& L);
	virtual std::vector<char> decrypt(const std::vector<char>& C) { return decrypt(C, charBuf(0)); };
	virtual std::vector<char> exportKey() { return charBuf(0); };
	virtual void importKey(std::vector<char> buf) {};
	using RsaOaepEncryptor::encrypt;
private:
};

class RsaVerifier : virtual public Verifier {
public:
	RsaVerifier(rsaPublicKey pk);
	virtual bool verify(std::istream& msg, const charBuf& sig) ;
	virtual std::vector<char> exportKey();
	virtual void importKey(charBuf buf);
	size_t keySize();
private:
	mpz_class _N;
	mpz_class _e;
	size_t _ksz;
};

rsaPrivateKey newRsaPrivateKey(size_t sz = 2048);


