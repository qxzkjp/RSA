#include "stdafx.h"
#include <vector>
#include "../RSA/randomNumbers.h"
#include "montgomery.h"
#include "../RSA/interfaces.h"

std::exception aShitFit("AAAGHRGABRL!!!!!");

//constant time positive modulo
mpz_class pmod(const mpz_class& i, const mpz_class& n)
{
	return (i % n + n) % n;
}

//constant-time, cache pattern identical conditional swap of two pointers
//the most excellent excellent idea behind this is courtesy of Muhammad Tauqir Ahmad
//the specific implementation (aka the easy bit) is mine
template<class T>
void conditionalSwap(bool condition, T** P, T** Q)
{
	uintptr_t* a = reinterpret_cast<uintptr_t*>(P);//these are pointers so that we swap in-place
	uintptr_t* b = reinterpret_cast<uintptr_t*>(Q);
	uintptr_t c = condition; //must be 0 or 1, per C++ spec
	--c; //must be 0 or MAX, which should be all ones
	uintptr_t ca = c & *a; //either *a or 0
	uintptr_t cb = c & *b; //either *b or 0
	*a = (*a) ^ (*b) ^ cb; //this is
	*b = (*a) ^ (*b) ^ ca; //where the
	*a = (*a) ^ (*b) ^ cb; //magic happens!
	//*P = reinterpret_cast<T*>(a);
	//*Q = reinterpret_cast<T*>(b);
}

MontgomeryCurve::MontgomeryCurve(
	mpz_class A, mpz_class B, mpz_class modulus,
	mpz_class GX, mpz_class period, mpz_class cofactor,
	std::vector<mp_bitcnt_t> zeromask, std::vector<mp_bitcnt_t> onemask)
	: A_(A), B_(B), modulus_(modulus), GX_(GX), period_(period), cofactor_(cofactor), zeromask_(zeromask), onemask_(onemask)
{
	mpz_class recip4;
	mpz_powm(recip4.get_mpz_t(), mpz_class(4).get_mpz_t(), mpz_class(modulus_ - 2).get_mpz_t(), modulus_.get_mpz_t());//get 1/4 mod p
	a24_ = pmod((A_ + 2)*recip4, modulus_); //a24=(A+2)/4
	pkSize_ = mpz_sizeinbase(modulus_.get_mpz_t(), 256);
	privkSize_ = mpz_sizeinbase(period_.get_mpz_t(), 256);
}

charBuf MontgomeryCurve::encrypt(charBuf key, mpz_class S) const
{
	Point P = pubkeyToPoint(key);
	Point Q = scalarMult(P, S);
	charBuf ret = pointToPubkey(Q);
	return ret;
}

charBuf MontgomeryCurve::getPublicKey(mpz_class S) const
{
	Point G = { GX_, 1 };
	Point pk = scalarMult(G, S);
	return pointToPubkey(pk);
}

mpz_class MontgomeryCurve::makePrivateKey() const
{
	//set up randomness
	gmp_randstate_t state;
	gmp_randinit_mt(state);
	mpz_t seed;
	mpz_init(seed);
	charBuf buf(512);
	getRandomBuffer(buf);//random seed from OS
	mpz_import(seed, 512, -1, 1, 0, 0, &buf[0]);
	gmp_randseed(state, seed);

	mpz_class S;
	mpz_urandomm(S.get_mpz_t(), state, period_.get_mpz_t()); //uniformly distributed random number
	maskPrivateKey(S); //what is the point of this?
	return S;
}

charBuf MontgomeryCurve::privateKeyToOs(mpz_class S) const
{
	size_t sz[1] = { 0 }; //size of buffer neeeded (set by function)
	uint8_t* rop = (uint8_t*)mpz_export(nullptr, sz, -1, 1, 0, 0, S.get_mpz_t()); //make buffer with number in it
	if (*sz > privkSize_)//is the number too large? it should never be
		throw aShitFit;
	charBuf O(privkSize_);
	memcpy(&O[pkSize_ - *sz], rop, *sz); //copy buffer into vector
	free(rop); //discard buffer allocated by GMP
	return O;
}

mpz_class MontgomeryCurve::osToPrivateKey(charBuf O) const
{
	if (O.size() > privkSize_) //if our public key is too large
		throw aShitFit;
	mpz_class S;
	mpz_import(S.get_mpz_t(), O.size(), -1, 1, 0, 0, &O[0]); //bytes to integer
	maskPrivateKey(S);
	return S;
}

//apply the stupid fucking masking bollocks from the spec
void MontgomeryCurve::maskPrivateKey(mpz_class& S) const
{
	for (auto it = onemask_.begin(); it != onemask_.end(); ++it)
		mpz_setbit(S.get_mpz_t(), *it);
	for (auto it = zeromask_.begin(); it != zeromask_.end(); ++it)
		mpz_clrbit(S.get_mpz_t(), *it);
}

MontgomeryCurve::Point MontgomeryCurve::pubkeyToPoint(const charBuf& key) const
{
	if (key.size() > pkSize_) //if our public key is too large
		throw aShitFit;
	mpz_class X;
	mpz_import(X.get_mpz_t(), key.size(), -1, 1, 0, 0, &key[0]); //yes, it's stored little-endian. not my choice.
	return{ X, 1 };
}

MontgomeryCurve::Point MontgomeryCurve::normalise(const Point& P) const
{
	if (P.Z == 0)//we can't normalise the point at infinity
		throw aShitFit;
	mpz_class Zinv;
	mpz_powm(Zinv.get_mpz_t(), P.Z.get_mpz_t(), mpz_class(modulus_ - 2).get_mpz_t(), modulus_.get_mpz_t());//get 1/Z mod p
	mpz_class x = pmod(P.X*Zinv, modulus_); //x=X/Z
	return{ x, 1 };
}

charBuf MontgomeryCurve::pointToPubkey(Point P) const
{
	if (P.Z == 0)//we can't use the point at infinity as a key
		throw aShitFit;
	P = normalise(P); //make sure P.Z==1
	size_t sz[1] = { 0 }; //size of buffer neeeded (set by function)
	uint8_t* rop = (uint8_t*)mpz_export(nullptr, sz, -1, 1, 0, 0, P.X.get_mpz_t()); //make buffer with number in it
	if (*sz > pkSize_)//is the number too large? it should never be
		throw aShitFit;
	charBuf O(pkSize_);
	memcpy(&O[pkSize_ - *sz], rop, *sz); //copy buffer into vector
	free(rop); //discard buffer allocated by GMP
	return O;
}

//ripped straight from the standard; don't even try and understand it: it works.
void MontgomeryCurve::doubleAndAdd(Point& P, Point& Q, const mpz_class& X) const
{
	mpz_class A = P.X + P.Z;
	mpz_class AA = A*A;
	mpz_class B = P.X - P.Z;
	mpz_class BB = B*B;
	mpz_class E = AA - BB;
	mpz_class C = Q.X + Q.Z;
	mpz_class D = Q.X - Q.Z;
	mpz_class DA = D * A;
	mpz_class CB = C * B;
	mpz_class X5 = (DA + CB);
	X5 *= X5;
	mpz_class Z5 = (DA - CB);
	Z5 *= Z5;
	Z5 *= X;
	mpz_class X4 = AA * BB;
	mpz_class Z4 = E * (BB + (a24_ * E));
	P.X = pmod(X4, modulus_);
	P.Z = pmod(Z4, modulus_);
	Q.X = pmod(X5, modulus_);
	Q.Z = pmod(Z5, modulus_);
}

//the secret number S *MUST* be less than the period
MontgomeryCurve::Point MontgomeryCurve::scalarMult(const Point& P, const mpz_class& S) const
{
	if (P.Z != 1)
		throw aShitFit;
	//number of bits used to represent the period, rounded up to a whole number of octets (for compat)
	//if we instead used the number of bits in S, the timing would depend on our secret number (crypto is all about edge cases)
	mp_bitcnt_t d = pkSize_ * 8;

	//ugly as it is, we must use pointers so that the constant time swap trick will work
	Point* R0 = new Point;
	Point* R1 = new Point;
	*R0 = { 1, 0 };//point at infinity
	*R1 = P;
	for (mp_bitcnt_t i = d; i > 0; --i)
	{
#pragma warning(disable:4800)
		bool bitIsSet = mpz_tstbit(S.get_mpz_t(), i - 1);//this returns int, because fuck C
#pragma warning(default:4800)
		conditionalSwap(bitIsSet, &R0, &R1);//we swap if the bit is ON, the spec is wrong.
		doubleAndAdd(*R0, *R1, P.X);
		conditionalSwap(bitIsSet, &R0, &R1);//THE FUCKING SPEC IS WRONG
	}
	Point ret = *R0;
	delete R0;
	delete R1;
	return ret;
}

X25519::X25519() : _curve(MontgomeryCurve(486662, 1,
	mpz_class("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED", 16), 9,
	mpz_class("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed", 16), 8,
	{ 0, 1, 2, 255 }, { 254 })){
	_privateKey = _curve.makePrivateKey();
	_publicKey = _curve.encrypt(_curve.getBasePoint(), _privateKey); //public key is base point times private key
}

std::vector<char> X25519::getPublic() const {
	return _publicKey;
}

std::vector<char> X25519::agreeKey(std::vector<char> otherPublic) const {
	return _curve.encrypt(otherPublic, _privateKey);
}
