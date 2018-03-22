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

template<class MGF, class Hash>
class RsaOaepEncryptor : virtual protected RsaEncryptor, virtual public TaggedEncryptor {
public: 
	RsaOaepEncryptor(rsaPublicKey pk);
	virtual std::vector<char> encrypt(const std::vector<char>& M, const std::vector<char>& L);
	virtual std::vector<char> encrypt(const std::vector<char>& M) { return encrypt(M, charBuf(0)); };
	virtual std::vector<char> exportKey() { return charBuf(0); };
	virtual void importKey(std::vector<char> buf) {};
#ifdef _DEBUG
	charBuf getLastSeed();
	void setNextSeed(charBuf seed);
#endif
protected:
	MGF _mgf;
	Hash _hash;
	size_t _hLen;
#ifdef _DEBUG
	charBuf _lastSeed;
	charBuf _nextSeed;
	bool _overrideSeed;
#endif
};

template<class MGF, class Hash>
class RsaOaepDecryptor : protected RsaDecryptor, public RsaOaepEncryptor<MGF, Hash>, virtual public TaggedDecryptor {
public:
	RsaOaepDecryptor(rsaPrivateKey pk);
	virtual std::vector<char> encrypt(const std::vector<char>& M, const std::vector<char>& L) { return RsaOaepEncryptor::encrypt(M, L); };
	virtual std::vector<char> encrypt(const std::vector<char>& M) { return RsaOaepEncryptor::encrypt(M); };
	virtual std::vector<char> decrypt(const std::vector<char>& C, const std::vector<char>& L);
	virtual std::vector<char> decrypt(const std::vector<char>& C) { return decrypt(C, charBuf(0)); };
	virtual std::vector<char> exportKey() { return charBuf(0); };
	virtual void importKey(std::vector<char> buf) {};
	using RsaOaepEncryptor::encrypt;
private:
};


//these signing and verification classes do nothing for now
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
	virtual std::vector<char> sign(std::vector<char>::const_iterator begin, std::vector<char>::const_iterator end) { return sign(); }
	virtual bool pass(std::istream& msg) {
		return true;
	}
	virtual std::vector<char> sign() { return charBuf(0); };
	virtual std::vector<char> exportKey() { return charBuf(0); };
	virtual void importKey(charBuf buf) {};
private:
};

//end of classes that don't work

rsaPrivateKey newRsaPrivateKey(size_t sz = 2048);

template<class MGF, class Hash>
RsaOaepEncryptor<MGF,Hash>::RsaOaepEncryptor(rsaPublicKey pk) :
	RsaEncryptor(pk),
	_hash(Hash()),
	_mgf(MGF()),
	_hLen(_hash.length())
#ifdef _DEBUG
	, _lastSeed(_hLen),
	_nextSeed(_hLen),
	_overrideSeed(false)
#endif
{
}

#ifdef _DEBUG
template<class MGF, class Hash>
charBuf RsaOaepEncryptor<MGF, Hash>::getLastSeed() {
	return _lastSeed;
}

template<class MGF, class Hash>
void RsaOaepEncryptor<MGF, Hash>::setNextSeed(charBuf seed) {
	std::copy(seed.begin(), seed.end(), _nextSeed.begin());
	_overrideSeed = true;
}
#endif

template<class MGF, class Hash>
std::vector<char> RsaOaepEncryptor<MGF, Hash>::encrypt(const std::vector<char>& M, const std::vector<char>& L) {
	auto dbLen = _ksz - _hLen - 1;
	if (M.size() > (_ksz - 2 * _hLen - 2)) {
		std::cerr << "rsaOaepEncrypt: message too long" << std::endl;
		return charBuf(0);
	}
	charBuf EM(_ksz);
	auto dbBegin = EM.begin() + _hLen + 1;
	auto seedBegin = EM.begin() + 1;
	auto seedEnd = dbBegin;
	auto dbEnd = EM.end();
	auto msgBegin = dbEnd - M.size();
	//              {--------db-------}
	//EM = 00||SEED||LHASH||000..01||M
	getRandomBuffer(seedBegin, seedEnd);			//put seed into beginning of EM (after 1 byte of padding)
#ifdef _DEBUG
	if (_overrideSeed) {
		std::copy(_nextSeed.begin(), _nextSeed.end(), seedBegin);
		_overrideSeed = false;
	}
	std::copy(seedBegin, seedEnd, _lastSeed.begin()); //copy out seed for debugging purposes
#endif
	_hash.reset();
	_hash.addData(L.begin(), L.end());
	_hash.finalise(dbBegin);										//put lHash at beginning of db
	*(msgBegin - 1) = 0x01;											//byte 0x01 signals beginning of message
	std::copy(M.begin(), M.end(), msgBegin);						//copy message to end of db
	_mgf.xorMaskWithSeed(seedBegin, seedEnd, dbBegin, dbLen);		//xor db with dbMask
	_mgf.xorMaskWithSeed(dbBegin, dbEnd, seedBegin, _hLen);			//xor seed with seedMask
	charBuf C = RsaEncryptor::encrypt(EM);
	return C;
}

template<class MGF, class Hash>
RsaOaepDecryptor<MGF, Hash>::RsaOaepDecryptor(rsaPrivateKey pk) : RsaOaepEncryptor<MGF,Hash>({ pk.N,pk.e }), RsaEncryptor(pk), RsaDecryptor(pk) {
}

template<class MGF, class Hash>
std::vector<char> RsaOaepDecryptor<MGF, Hash>::decrypt(const std::vector<char>& C, const std::vector<char>& L) {
	auto dbLen = _ksz - _hLen - 1;
	if (_ksz < 2 * _hLen + 2) {
		std::cerr << "rsaOaepDecrypt: decryption error (hash too big or key too small)" << std::endl;
		return charBuf(0);
	}
	charBuf lHash = doHash<Hash>(L);
	charBuf EM = RsaDecryptor::decrypt(C);
	auto dbBegin = EM.begin() + _hLen + 1;
	auto seedBegin = EM.begin() + 1;
	auto seedEnd = dbBegin;
	auto labelEnd = dbBegin + _hLen;
	auto dbEnd = EM.end();
	if (EM[0] != 0x00) {
		std::cerr << "rsaOaepDecrypt: decryption error (invalid initial byte)" << std::endl;
		return charBuf(0);
	}
	_mgf.xorMaskWithSeed(dbBegin, dbEnd, seedBegin, _hLen);			//xor away seedMask
	_mgf.xorMaskWithSeed(seedBegin, seedEnd, dbBegin, dbLen);		//xor away dbMask
	bool checkLabel = !memcmp(&dbBegin[0], &lHash[0], _hLen);		//check if lHash matches
	if (!checkLabel) {
		std::cerr << "rsaOaepDecrypt: decryption error (label error)" << std::endl;
		return charBuf(0);
	}
	auto msgBegin = labelEnd;
	//run forward until the byte after 0x01
	//due to size checks, labelEnd cannot be pointing beyond the end of the vector
	while (*msgBegin++ != 0x01) {
		if (msgBegin == EM.end()) {
			std::cerr << "rsaOaepDecrypt: decryption error (no marker byte)" << std::endl;
			return charBuf(0);
		}
	}
	size_t mLen = dbEnd - msgBegin;
	charBuf M(mLen);
	memcpy(&M[0], &msgBegin[0], mLen);								//copy out message from end of EM
	return M;
}
