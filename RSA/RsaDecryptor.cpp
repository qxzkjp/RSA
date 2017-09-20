#include "stdafx.h"
#include "RsaDecryptor.h"
#include "randomNumbers.h"
#include "mpzConvert.h"
#include "CryptContext.h"
#include "memoryhelper.h"
#include "../SHA1/Sha1Class.h"

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

RsaEncryptor::RsaEncryptor(rsaPublicKey pk) : _N(pk.N), _e(pk.e) {
	if (_N == 0 || _e > _N)
		throw 5;//throw random obbject to crash if invalid key is passed
	_ksz = mpz_sizeinbase(_N.get_mpz_t(), 256);
}

std::vector<char> RsaEncryptor::encrypt(const std::vector<char>& M)
{
	mpz_class m = vectorToMpzClass(M);
	mpz_class c;
	mpz_powm(c.get_mpz_t(), m.get_mpz_t(), _e.get_mpz_t(), _N.get_mpz_t());
	std::vector<char> C = mpzClassToVector(c);
	return C;
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
	pk.p = getBigPrime(sz / 2);
	pk.q = getBigPrime(sz / 2);
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

RsaDecryptor::RsaDecryptor(rsaPrivateKey pk) : RsaEncryptor({pk.N,pk.e}), _d(pk.d), _p(pk.p), _q(pk.q), _dp(pk.dp), _dq(pk.dq), _qinv(pk.qinv) {
}

std::vector<char> RsaDecryptor::exportKey() { 
	std::cerr << "RsaDecryptor::exportKey" << std::endl;
	return std::vector<char>(0);
}
void RsaDecryptor::importKey(std::vector<char> buf) {}

std::vector<char> RsaDecryptor::decrypt(const std::vector<char>& C)
{
	mpz_class c = vectorToMpzClass(C);
	mpz_class m, m1, m2, m3, h;
	mpz_powm(m1.get_mpz_t(), c.get_mpz_t(), _dp.get_mpz_t(), _p.get_mpz_t());
	mpz_powm(m2.get_mpz_t(), c.get_mpz_t(), _dq.get_mpz_t(), _q.get_mpz_t());
	//m3 is a dummy, to prevent timing attacks. let's hope the compiler does not optimise it away.
	m3 = m1;
	if (m1 < m2) {
		m1 = m1 + _p;
	}
	else {
		m3 = m3 + _p;
	}
	(void)m3; //magic incantation to prevent optimising away m3
	h = (_qinv*(m1 - m2)) % _p;
	m = m2 + h*_q;
	std::vector<char> M = mpzClassToVector(m, _ksz);//we pad the number to ksz bytes if neccessary
	return M;
}

void RsaDecryptor::generateKey(size_t sz) {}

RsaOaepEncryptor::RsaOaepEncryptor(rsaPublicKey pk, mgfPtr mgf, hashPtr hash) : RsaEncryptor(pk), _mgf(mgf), _hash(hash), _hLen(hash->length()) {

}

std::vector<char> RsaOaepEncryptor::encrypt(const std::vector<char>& M, const std::vector<char>& L) {
	auto dbLen = _ksz - _hLen - 1;
	if (M.size() > (_ksz - 2 * _hLen - 2)) {
		std::cerr << "rsaOaepEncrypt: message too long" << std::endl;
		return charBuf(0);
	}
	//charBuf lHash = doHash(hash, L);
	charBuf EM(_ksz);
	//charBuf DB(k - _hLen - 1);
	//std::copy(lHash.begin(), lHash.end(), C.begin()+_hLen+1);
	//*(C.end() - M.size() - 1) = 0x01;
	//std::copy(M.begin(), M.end(), C.end() - M.size());
	auto dbBegin = EM.begin() + _hLen + 1;
	auto seedBegin = EM.begin() + 1;
	auto seedEnd = dbBegin;
	auto dbEnd = EM.end();
	auto msgBegin = dbEnd - M.size();
	//              {--------db-------}
	//EM = 00||SEED||LHASH||000..01||M
	getRandomBuffer(seedBegin, seedEnd);			//put seed into beginning of EM (after 1 byte of padding)
	_hash->reset();
	_hash->addData(L.begin(), L.end());
	_hash->finalise(dbBegin);						//put lHash at beginning of db
	*(msgBegin - 1) = 0x01;							//byte 0x01 signals beginning of message
	std::copy(M.begin(), M.end(), msgBegin);		//copy message to end of db
	_mgf(seedBegin, seedEnd, dbBegin, dbLen);		//xor db with dbMask
	_mgf(dbBegin, dbEnd, seedBegin, _hLen);			//xor seed with seedMask
	charBuf C = RsaEncryptor::encrypt(EM);
	return C;
}

RsaOaepDecryptor::RsaOaepDecryptor(rsaPrivateKey pk, mgfPtr mgf, hashPtr hash) : RsaOaepEncryptor({ pk.N,pk.e }, mgf, hash), RsaEncryptor({ pk.N,pk.e }), RsaDecryptor(pk) {
}

std::vector<char> RsaOaepDecryptor::decrypt(const std::vector<char>& C, const std::vector<char>& L) {
	//auto k = rsa.keySize();
	auto hLen = _hash->length();
	auto dbLen = _ksz - hLen - 1;
	if (_ksz < 2 * hLen + 2) {
		std::cerr << "rsaOaepDecrypt: decryption error (hash too big or key too small)" << std::endl;
		return charBuf(0);
	}
	charBuf lHash = doHash(_hash, L);
	charBuf EM = RsaDecryptor::decrypt(C);
	auto dbBegin = EM.begin() + hLen + 1;
	auto seedBegin = EM.begin() + 1;
	auto seedEnd = dbBegin;
	auto labelEnd = dbBegin + hLen;
	auto dbEnd = EM.end();
	if (EM[0] != 0x00) {
		std::cerr << "rsaOaepDecrypt: decryption error (invalid initial byte)" << std::endl;
		return charBuf(0);
	}
	_mgf(dbBegin, dbEnd, seedBegin, hLen);							//xor away seedMask
	_mgf(seedBegin, seedEnd, dbBegin, dbLen);						//xor away dbMask
	bool chackLabel = !memcmp(&dbBegin[0], &lHash[0], hLen);		//check if lHash matches
	if (!chackLabel) {
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
