// RSA.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include<memory>
#include "CryptContext.h"
#include "randomNumbers.h"
#include "Buffer.h"
#include "mpzConvert.h"
#include "RsaDecryptor.h"
#include "../SHA1/Sha1Class.h"

/*
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

class RSA
{
public:
	RSA(size_t sz = 2048)
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
	Buffer encrypt(const Buffer& M)
	{
		mpz_class m = bufferToMpzClass(M);
		mpz_class c;
		mpz_powm(c.get_mpz_t(), m.get_mpz_t(), _e.get_mpz_t(), _N.get_mpz_t());
		Buffer C = mpzClassToBuffer(c);
		return C;
	}
	Buffer decrypt(const Buffer& C)
	{
		mpz_class c = bufferToMpzClass(C);
		mpz_class m, m1, m2, m3, h;
		mpz_powm(m1.get_mpz_t(), c.get_mpz_t(), _dp.get_mpz_t(), _p.get_mpz_t());
		mpz_powm(m2.get_mpz_t(), c.get_mpz_t(), _dq.get_mpz_t(), _q.get_mpz_t());
		//m3 is a dummy, to prevent timing attacks. let's hope the compiler does not optimise it away
		m3 = m1;
		if (m1 < m2) {
			m1 = m1 + _p;
		}else {
			m3 = m3 + _p;
		}
		h = (_qinv*(m1 - m2)) % _p;
		m = m2 + h*_q;
		Buffer M = mpzClassToBuffer(m);
		return M;
	}
private:
	mpz_class _p;
	mpz_class _q;
	mpz_class _N;
	mpz_class _e;
	mpz_class _d;
	mpz_class _dp;
	mpz_class _dq;
	mpz_class _qinv;
};*/

typedef std::shared_ptr<HashFunction> hashPtr;

std::vector<char> MGF1(hashPtr hash, std::vector<char> mgfSeed, size_t maskLen) {
	if (maskLen == 0)
		return std::vector<char>(0);
	std::vector<char> ret(maskLen);
	size_t hLen = hash->length();
	hash->reset();
	hash->addData(mgfSeed);
	if (maskLen > hLen << 32)
		throw 5; //throw random object and die
	size_t q = (maskLen + hLen - 1) / hLen; //ceiling of maskLen/hLen
	std::vector<char> ctrvec(4);
	std::vector<char> hashout(hLen);
	HashFunction* hash2;
	auto it = ret.begin();
	//we fill up the output buffer in hlen-sized chunks; we can fit q-1 whole chunks in the buffer
	for (uint32_t counter = 0; counter < q-1; ++counter) {
		hash2 = hash->clone();
		reverseMemcpy(&ctrvec[0], &counter, 4);//only works on little-endian
		hash2->addData(ctrvec);
		hash2->finalise(it);
//		size_t check = it - ret.begin();
		it += hLen;
	}
	// now we do the final block, which might not be a whole block
	hash2 = hash->clone();
	size_t counter = q - 1;
	reverseMemcpy(&ctrvec[0], &counter, 4);//only works on little-endian
	hash2->addData(ctrvec);
	hash2->finalise(hashout.begin());
	size_t r = (q * hLen) - maskLen;
	std::copy(hashout.begin(), hashout.begin() + (hLen - r), it);
	return ret;
}

void printVec(std::vector<char> buf, std::ostream& os = std::cout) {
	std::ios::fmtflags flg(os.flags());
	os << std::hex;
	for (int i = 0; i < buf.size(); ++i) {
		if ((buf[i] & 0xF0) == 0)
			os << "0";
		os << (int)(unsigned char)buf[i];
		if (i % 4 == 3 && i % 32 != 31)
			os << " ";
		if (i % 32 == 31)
			os << std::endl;
	}
	os.flags(flg);
}

int main()
{
	//RsaDecryptor key(2048);
	/*Buffer M ("Hello World!");
	Buffer C;
	Buffer Mprime;
	C = key.encrypt(M);
	Mprime = key.decrypt(C);
	std::cout << std::hex << "M:  " << bufferToMpzClass(M) << std::endl << "M': " << bufferToMpzClass(Mprime) << std::endl;
	if (M == Mprime)
		std::cout << "Success!" << std::endl;
	else
		std::cout << "Failure!" << std::endl;*/
	size_t testLen = (UCHAR_MAX+1)*20;
	std::vector<char> v = MGF1(hashPtr(new Sha1Class), { 1,2,3,4,5,6,7,8,9,10 }, testLen);
	Sha1Class sha;
	std::vector<char> tmp(20);
	std::vector<char> w(0);
	size_t n = 255;
	for (size_t i = 0; i <= CHAR_MAX; ++i) {
		sha.addData({ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, (char)i });
		sha.finalise(tmp.begin());
		w.insert(w.end(), tmp.begin(), tmp.end());
		sha.reset();
	}
	for (char i = CHAR_MIN; i < 0; ++i) {
		sha.addData({ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, i });
		sha.finalise(tmp.begin());
		w.insert(w.end(), tmp.begin(), tmp.end());
		sha.reset();
	}
	bool calcTest = memcmp(&v[0], &w[0], testLen) == 0;
	std::cout << "MGF1 calculation test ";
	if (calcTest)
		std::cout << "successful";
	else
		std::cout << "failed";
	std::cout << std::endl;
	bool truncTest = true;
	for (int i = 1; i < testLen; ++i) {
		w = MGF1(hashPtr(new Sha1Class), { 1,2,3,4,5,6,7,8,9,10 }, i);
		truncTest = truncTest && (memcmp(&v[0], &w[0], i) == 0);
	}
	std::cout << "MGF1 truncation test ";
	if (truncTest)
		std::cout << "successful";
	else
		std::cout << "failed";
	std::cout << std::endl;
	system("pause");
	return 0;
}

