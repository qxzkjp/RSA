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
	RsaEncryptor(rsaPrivateKey pk);
	virtual std::vector<char> encrypt(const std::vector<char>& M);
	virtual std::vector<char> exportKey();
	virtual void importKey(std::vector<char> buf);
	size_t keySize();
protected:
	rsaPrivateKey _key;
	size_t _ksz;
private:
	void checkAndSet();
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
};

class RsaOaepEncryptor : virtual protected RsaEncryptor, virtual public TaggedEncryptor {
public: 
	RsaOaepEncryptor(rsaPublicKey pk, mgfPtr mgf = mgf1sha1, hashPtr hash=std::make_shared<Sha1Class>());
	virtual std::vector<char> encrypt(const std::vector<char>& M, const std::vector<char>& L);
	virtual std::vector<char> encrypt(const std::vector<char>& M) { return encrypt(M, charBuf(0)); };
	virtual std::vector<char> exportKey() { return charBuf(0); };
	virtual void importKey(std::vector<char> buf) {};
#ifdef _DEBUG
	charBuf getLastSeed();
	void setNextSeed(charBuf seed);
#endif
protected:
	mgfPtr _mgf;
	hashPtr _hash;
	size_t _hLen;
#ifdef _DEBUG
	charBuf _lastSeed;
	charBuf _nextSeed;
	bool _overrideSeed;
#endif
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
	RsaVerifier(rsaPrivateKey pk);
	virtual bool verify(std::istream& msg, const charBuf& sig)=0;
	virtual std::vector<char> exportKey() = 0;
	virtual void importKey(charBuf buf) = 0;
	size_t keySize() {
		return _ksz;
	}
private:
	rsaPrivateKey _key;
	size_t _ksz;
};

class RsaPssVerifier : public RsaVerifier {
public:
	RsaPssVerifier(rsaPublicKey pk, hashFunc hash, mgfPtr mgf, size_t sLen) : RsaVerifier(pk), _hash(hash), _mgf(mgf), _sLen(sLen) {}
	RsaPssVerifier(rsaPrivateKey pk, hashFunc hash, mgfPtr mgf, size_t sLen) : RsaVerifier(pk), _hash(hash), _mgf(mgf), _sLen(sLen) {}
	virtual bool verify(std::istream& msg, const charBuf& sig) { return true; };
	virtual std::vector<char> exportKey() { return charBuf(0); };
	virtual void importKey(charBuf buf) {};
private:
	hashFunc _hash;
	mgfPtr _mgf;
	size_t _sLen;
};

class RsaPssSigner : public RsaPssVerifier, virtual public Signer {
public:
	virtual std::vector<char> sign(std::istream& msg) { pass(msg); return sign(); }
	virtual bool pass(std::istream& msg) {
		return true;
	}
	virtual std::vector<char> sign() { return charBuf(0); };
	virtual std::vector<char> exportKey() { return charBuf(0); };
	virtual void importKey(charBuf buf) {};
private:
};

rsaPrivateKey newRsaPrivateKey(size_t sz = 2048);
