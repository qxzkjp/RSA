// EC.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <exception>
#include <vector>
#include "montgomery.h"
#include <stdint.h>
#include <mpirxx.h>
#include "../RSA/interfaces.h"


charBuf hex2os(const char* s)
{
	size_t sz = strlen(s);
	charBuf ret(sz / 2);
	if (sz > 1)
	{
		char tmp[3] = { 0, 0, 0 };
		for (size_t i = 0; i < sz - 1; i += 2)
		{
			memcpy(tmp, s + i, 2);
			ret[i / 2] = std::strtol(tmp, nullptr, 16) & 0xFF;
		}
	}
	return ret;
}

struct wEC;

//weirstrauss-form elliptic curve point
struct wECpoint
{
	mpz_class x;
	mpz_class y;
	const wEC* curve;
};

//weirstrauss form EC
struct wEC
{
	mpz_class a;
	mpz_class b;
	mpz_class modulus;
	wECpoint G;
	mpz_class n;
	mpz_class h;
};

//Compute P+P on an arbitrary Weierstrass-form curve over a prime field
//point doubling depends on a, but not b
wECpoint WeierstrassDouble(wECpoint P)
{
	//this is so obviously open to timing atacks!
	if (P.y == 0)
		return{ 0, 0 };//we represent the "point at infinity" as (0,0)
	mpz_class lambda = 3 * P.x * P.x + P.curve->a;
	mpz_class recip;
	mpz_class denom = 2 * P.y;
	//get (2*y.p)^-1
	mpz_invert(recip.get_mpz_t(), denom.get_mpz_t(), P.curve->modulus.get_mpz_t());
	lambda *= recip; // lambda /= 2*y.p
	wECpoint R;
	R.curve = P.curve;
	R.x = (lambda*lambda - P.x - P.x) % P.curve->modulus;
	R.y = (lambda*(P.x - R.x) - P.y) % P.curve->modulus;
	if (R.x < 0)
		R.x += P.curve->modulus;
	if (R.y < 0)
		R.y += P.curve->modulus;
	return R;
}

//Add two points on an arbitrary weierstrass  EC over a prime field
//for efficiency's sake this function does not check both points are on the same curve
wECpoint WeierstrassAdd(wECpoint P, wECpoint Q)
{
	if (P.x == Q.x && P.y == Q.y)
		return WeierstrassDouble(P);
	//these three conditions need to be made into something constant time
	if (P.x == Q.x)
		return{ 0, 0 }; //point at infinity
	if (P.x == 0 && P.y == 0)
		return Q;
	if (Q.x == 0 && Q.y == 0)
		return P;
	//bool is_inf = (P.x == 0 & P.y == 0) | (Q.x == 0 && Q.y == 0);
	mpz_class lambda = Q.y - P.y;
	mpz_class denom = Q.x - P.x;
	mpz_class recip;
	mpz_invert(recip.get_mpz_t(), denom.get_mpz_t(), P.curve->modulus.get_mpz_t());
	lambda *= recip; //lambda /= denom
	wECpoint R;
	R.curve = P.curve;
	//these formulae are from wikipedia; lambda==(Q.y-P.y)/(Q.x-P.x)
	R.x = ((lambda*lambda) - P.x - Q.x) % R.curve->modulus;
	R.y = (lambda*(P.x - R.x) - P.y) % R.curve->modulus;
	if (R.x < 0)
		R.x += P.curve->modulus;
	if (R.y < 0)
		R.y += P.curve->modulus;
	return R;
}

//scalar multiplication for weierstrass  curves using the montgomery ladder
//NOTE: not yet constant time, as add and double are not constant time
wECpoint scalarMult(wECpoint P, const mpz_class& n)
{
	mp_bitcnt_t d = mpz_sizeinbase(n.get_mpz_t(), 2); //number of bits used to represent n
	wECpoint R0 = { 0, 0, P.curve };
	wECpoint R1 = P;
	for (mp_bitcnt_t i = d; i > 0; --i)
		if (mpz_tstbit(n.get_mpz_t(), i - 1)) //if the ith bit is set
		{
			R0 = WeierstrassAdd(R0, R1);
			R1 = WeierstrassDouble(R1);
		}
		else{
			R1 = WeierstrassAdd(R0, R1);
			R0 = WeierstrassDouble(R0);
		}
		return R0;
}

wECpoint operator+(wECpoint P, wECpoint Q)
{
	return WeierstrassAdd(P, Q);
}

wECpoint operator+=(wECpoint& P, wECpoint Q)
{
	P = WeierstrassAdd(P, Q);
	return P;
}

wECpoint operator*= (wECpoint& P, const mpz_class& n)
{
	P = scalarMult(P, n);
	return P;
}

wECpoint operator*(const mpz_class& n, wECpoint P)
{
	return scalarMult(P, n);
}

wECpoint operator*(uint64_t n, wECpoint P)
{
	return mpz_class(n)*P;
}

/*
curve25519 test vectors:

testCurve25519(
hex2os("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
hex2os("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"),
hex2os("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"));

testCurve25519(
hex2os("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"),
hex2os("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"),
hex2os("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"));

curve448 test vectors:

testCurve448(
	hex2os("3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3"),
	hex2os("06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086"),
	hex2os("ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239fe14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f"));

testCurve448(
	hex2os("203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c538345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f"),
	hex2os("0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db"),
	hex2os("884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d"));

*/

/*When receiving [a public key], implementations of curve25519
MUST mask the most-significant bit in the final byte.*/

/*For curve25519,
   in order to decode 32 bytes into an integer scalar, set the three
   least significant bits of the first byte and the most significant bit
   of the last to zero, set the second most significant bit of the last
   byte to 1 and, finally, decode as little-endian.
   zeromask:
   0,1,2,3,4,5,6,7 ... 254, 255
   ^ ^ ^                      ^
   onemask:
   255,254,253,252,251,250,249,248
         ^  */

/*for curve448,
   set the two least significant bits of the first byte to 0, and the
   most significant bit of the last byte to 1. (56 bytes)
   zeromask:
   0,1,2,3,4,5,6,7
   ^ ^
   onemask:
   447,446,445,444,443,442,441,440
   ^  */

const MontgomeryCurve C448(156326, 1,
	(mpz_class(1) << 448) - (mpz_class(1) << 224) - 1, 5,
	(mpz_class(1) << 446) - mpz_class("8335dc163bb124b65129c96fde933d8d723a70aadc873d6d54a7bb0d", 16), 4,
	{ 0, 1 }, { 447 });
const MontgomeryCurve C25519(486662, 1,
	mpz_class("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED", 16), 9,
	mpz_class("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed", 16), 8,
	{ 0, 1, 2, 255 }, { 254 });

template<class T>
void doTest(T result, T knownGood)
{
	if (result == knownGood)
		std::cout << "Success!" << std::endl;
	else
		std::cout << "Failure!" << std::endl;
}

void testCurve25519(const charBuf& privkey, charBuf pubkey, const charBuf& result)
{
	*pubkey.rbegin() &= 0x7F;//highest bit must be clear for backcompat
	mpz_class S = C25519.osToPrivateKey(privkey);
	charBuf prod = C25519.encrypt(pubkey, S);
	//std::cout << prod << std::endl;
	doTest(prod, result);
}

void testCurve448(const charBuf& privkey, charBuf pubkey, const charBuf& result)
{
	mpz_class S = C448.osToPrivateKey(privkey);
	charBuf prod = C448.encrypt(pubkey, S);
	//std::cout << prod << std::endl;
	doTest(prod, result);
}

int _tmain(int argc, _TCHAR* argv[])
{
	testCurve25519(
		hex2os("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
		hex2os("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"),
		hex2os("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"));

	testCurve25519(
		hex2os("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"),
		hex2os("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"),
		hex2os("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"));

	testCurve448(
		hex2os("3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3"),
		hex2os("06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086"),
		hex2os("ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239fe14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f"));

	testCurve448(
		hex2os("203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c538345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f"),
		hex2os("0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db"),
		hex2os("884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d"));
	return 0;
}

