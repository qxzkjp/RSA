#include "stdafx.h"
#include "RsaDecryptor.h"
#include "randomNumbers.h"
#include "mpzConvert.h"
#include "memoryhelper.h"
#include "../SHA1/Sha1Class.h"
#include <thread>

bool oldLikelyPrime(mpz_class n) {
	return mpz_likely_prime_p(n.get_mpz_t(), globalContext.gmpState(), 0);
}

mpz_class getBigPrime(size_t bits) {
	mpz_class p = 0;
	size_t sz = (bits + 7) / 8; //ceiling of bits/8, so prime may be larger than needed
	charBuf buf(sz);
	while (!oldLikelyPrime(p)) {
		getRandomBuffer(buf);
		//if we have a appropriately-sized buffer, we feed in data a limb at a time, otherwise a byte at a time
		if (sz % SIZEOF_MP_LIMB_T == 0) {
			size_t bigSz = sz / SIZEOF_MP_LIMB_T;
			mp_limb_t* bigBuf = (mp_limb_t*)&buf[0];
			//this is done little-endian style, as limbToMpzClass is little-endian
			bigBuf[bigSz - 1] |= 0xC0LL << (8 * (SIZEOF_MP_LIMB_T - 1));		//set two high bits, to ensure number is large enough
			bigBuf[0] |= 0x01;													//set low bit, to ensure number is odd
			p = limbToMpzClass(bigBuf, bigSz);
		}
		else {
			//note that this branch is big-endian; this is not a mistake
			buf[0] |= 0xC0;					//set two high bits, to ensure number is large enough
			buf[sz - 1] |= 0x01;			//set low bit, to ensure number is odd
			p = vectorToMpzClass(buf);
		}
	}
	return p;
}

void getBigPrimeThread(size_t bits, mpz_class& x) {
	x = getBigPrime(bits);
}

charBuf RSAEP(const charBuf& M, const mpz_class& N, const mpz_class& e)
{
	mpz_class m = vectorToMpzClass(M);
	mpz_class c;
	mpz_powm(c.get_mpz_t(), m.get_mpz_t(), e.get_mpz_t(), N.get_mpz_t());
	std::vector<char> C = mpzClassToVector(c);
	return C;
}

charBuf RSADP(
	const charBuf& C,
	const mpz_class& N,
	const mpz_class& p,
	const mpz_class& q,
	const mpz_class& dp,
	const mpz_class& dq,
	const mpz_class& qInv,
	size_t k
) {
	mpz_class c = vectorToMpzClass(C);
	mpz_class m, m1, m2, m3, h;
	mpz_powm(m1.get_mpz_t(), c.get_mpz_t(), dp.get_mpz_t(), p.get_mpz_t());
	mpz_powm(m2.get_mpz_t(), c.get_mpz_t(), dq.get_mpz_t(), q.get_mpz_t());
	h = (qInv*(m1 - m2)) % p;
	auto h2 = h; //dummy var
	if (h < 0)	//make sure h is positive, in constant-time
		h += p;
	else
		h2 += p;
	m = m2 + h*q;
	std::vector<char> M = mpzClassToVector(m, k);//we pad the number to k bytes if neccessary
	return M;
}

void RsaEncryptor::checkAndSet() {
	if (_key.N == 0 || _key.e > _key.N)
		throw 5;//throw random obbject to crash if invalid key is passed
	_ksz = mpz_sizeinbase(_key.N.get_mpz_t(), 256);
}

RsaEncryptor::RsaEncryptor(rsaPublicKey pk) : _key({ pk.N,pk.e,0,0,0,0,0,0 }) {
	checkAndSet();
}

RsaEncryptor::RsaEncryptor(rsaPrivateKey pk) : _key(pk) {
	checkAndSet();
}

std::vector<char> RsaEncryptor::encrypt(const std::vector<char>& M)
{
	return RSAEP(M, _key.N, _key.e);
}

std::vector<char> RsaEncryptor::exportKey() {
	std::cerr << "RsaEncryptor::exportKey" << std::endl;
	return std::vector<char>(0);
}
void RsaEncryptor::importKey(std::vector<char> buf) {
	std::cerr << "RsaEncryptor::importKey" << std::endl;
}

size_t RsaEncryptor::keySize() {
	return _ksz;
}

rsaPrivateKey newRsaPrivateKey(size_t sz)
{
	rsaPrivateKey pk;
	//pk.p = getBigPrime(sz / 2);
	//pk.q = getBigPrime(sz / 2);
	std::thread t1(&getBigPrimeThread, sz/2, std::ref(pk.p));
	std::thread t2(&getBigPrimeThread, sz/2, std::ref(pk.q));
	t1.join();
	t2.join();
	pk.N = pk.p*pk.q;
	pk.e = 65537;
	mpz_class lambda;
	mpz_class gcd;
	--pk.p;
	--pk.q;
	mpz_lcm(lambda.get_mpz_t(), pk.p.get_mpz_t(), pk.q.get_mpz_t());
	mpz_gcdext(gcd.get_mpz_t(), pk.d.get_mpz_t(), NULL, pk.e.get_mpz_t(), lambda.get_mpz_t()); //e=d^-1 mod lambda(N)
	if (pk.d < 0)
		pk.d += lambda;
	pk.dp = pk.d % pk.p; // d mod p-1
	pk.dq = pk.d % pk.q; // d mod q-1
	++pk.p;
	++pk.q;
	mpz_gcdext(gcd.get_mpz_t(), pk.qinv.get_mpz_t(), NULL, pk.q.get_mpz_t(), pk.p.get_mpz_t()); //q^-1 mod p
	if (pk.qinv < 0)
		pk.qinv += pk.p;
	return pk;
}

RsaDecryptor::RsaDecryptor(rsaPrivateKey pk) : RsaEncryptor(pk) {
}

std::vector<char> RsaDecryptor::exportKey() { 
	std::cerr << "RsaDecryptor::exportKey" << std::endl;
	return std::vector<char>(0);
}
void RsaDecryptor::importKey(std::vector<char> buf) {
	std::cerr << "RsaDecryptor::importKey" << std::endl;
}

std::vector<char> RsaDecryptor::decrypt(const std::vector<char>& C)
{
	return RSADP(C, _key.N, _key.p, _key.q, _key.dp, _key.dq, _key.qinv, _ksz);
}

void RsaDecryptor::generateKey(size_t sz) {}


RsaVerifier::RsaVerifier(rsaPublicKey pk) : _key({ pk.N,pk.e,0,0,0,0,0,0 }) {
	if (_key.N == 0 || _key.e > _key.N)
		throw 5;//throw random obbject to crash if invalid key is passed
	_ksz = mpz_sizeinbase(_key.N.get_mpz_t(), 256);
}

RsaVerifier::RsaVerifier(rsaPrivateKey pk) : _key(pk) {
	if (_key.N == 0 || _key.e > _key.N)
		throw 5;//throw random obbject to crash if invalid key is passed
	_ksz = mpz_sizeinbase(_key.N.get_mpz_t(), 256);
}

bool RsaVerifier::verify(std::istream& msg, const charBuf& sig) {
	std::cerr << "RsaVerifier::verify: function not implemented" << std::endl;
	return false;
}

std::vector<char> RsaVerifier::exportKey() {
	std::cerr << "RsaVerifier::exportKey: function not implemented" << std::endl;
	return charBuf(0);
};

void RsaVerifier::importKey(charBuf buf) {
	std::cerr << "RsaVerifier::exportKey: function not implemented" << std::endl;;
};

