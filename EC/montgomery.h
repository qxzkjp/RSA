#ifndef MONTGOMERY_H
#define MONTGOMERY_H
#include "mpirxx.h"
#include "../RSA/interfaces.h"

class EllipticCurve
{
public:
	virtual charBuf encrypt(charBuf key, mpz_class S) const = 0;
	virtual charBuf getPublicKey(mpz_class S) const = 0;
	virtual mpz_class makePrivateKey() const = 0;
};

class MontgomeryCurve : public EllipticCurve
{
private:
	struct Point{ mpz_class X; mpz_class Z; };
public:
	MontgomeryCurve(
		mpz_class A, mpz_class B, mpz_class modulus,
		mpz_class GX, mpz_class period, mpz_class cofactor,
		std::vector<mp_bitcnt_t> zeromask = {}, std::vector<mp_bitcnt_t> onemask = {});
	charBuf encrypt(charBuf key, mpz_class S) const;
	charBuf getPublicKey(mpz_class S) const;
	mpz_class makePrivateKey() const;
	mpz_class osToPrivateKey(charBuf O) const;
	charBuf privateKeyToOs(mpz_class S) const;
	charBuf getBasePoint() const {
		return privateKeyToOs(GX_);
	}
private:
	Point pubkeyToPoint(const charBuf& key) const;
	charBuf pointToPubkey(Point P) const;
	Point scalarMult(const Point& P, const mpz_class& S) const;
	void doubleAndAdd(Point& P, Point& Q, const mpz_class& X) const;
	Point normalise(const Point& P) const;
	void maskPrivateKey(mpz_class& S) const;
	mpz_class A_;
	mpz_class B_;
	mpz_class modulus_;
	mpz_class GX_;
	mpz_class period_;
	mpz_class cofactor_;
	mpz_class a24_;
	size_t pkSize_; //public key size in BYTES
	size_t privkSize_; //public key size in BYTES
	std::vector<mp_bitcnt_t> onemask_;
	std::vector<mp_bitcnt_t> zeromask_;
};


class X25519 : public KeyAgreement
{
public:
	X25519();
	virtual std::vector<char> exportKey() { return charBuf(); };
	virtual void importKey(std::vector<char> buf) {};
	virtual std::vector<char> getPublic() const;
	virtual std::vector<char> agreeKey(std::vector<char> otherPublic) const;
	virtual ~X25519() {};
private:
	MontgomeryCurve _curve;
	mpz_class _privateKey;
	charBuf _publicKey;
};


#endif //MONTGOMERY_H