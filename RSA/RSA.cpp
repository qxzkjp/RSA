// RSA.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <memory>
#include "CryptContext.h"
#include "randomNumbers.h"
#include "Buffer.h"
#include "mpzConvert.h"
#include "RsaDecryptor.h"
#include "../SHA1/Sha1Class.h"
#include <cstring>
#include "memoryhelper.h"
#include "mgf1.h"


void printVec(charBuf buf, std::ostream& os = std::cout) {
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

//this function is generally stupid and is only for use in MGF1 testing
inline char sizeToChar(size_t n) {
	char m;
	if (n <= CHAR_MAX)
		m = (char)n;
	else
		m = (char)CHAR_MIN + ((char)n - CHAR_MAX - 1);
	return m;
}

void mgf1Test() {
	int testLen = 0x10000;
	charBuf v = MGF1(std::make_shared<Sha1Class>(), { 1,2,3,4,5,6,7,8,9,10 }, testLen);
	Sha1Class sha;
	charBuf tmp(20);
	charBuf w(0);
	size_t n = 255;
	for (size_t j = 0; j <= UCHAR_MAX; ++j) {
		char sj = sizeToChar(j);
		for (size_t i = 0; i <= UCHAR_MAX; ++i) {
			char si = sizeToChar(i);
			sha.addData({ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, sj, si });
			sha.finalise(tmp.begin());
			w.insert(w.end(), tmp.begin(), tmp.end());
			sha.reset();
		}
	}
	bool calcTest = memcmp(&v[0], &w[0], testLen) == 0;
	std::cout << "MGF1 calculation test ";
	if (calcTest)
		std::cout << "successful";
	else
		std::cout << "failed";
	std::cout << std::endl;
	bool truncTest = true;
	//hashPtr h(new Sha1Class);
	hashPtr h = std::make_shared<Sha1Class>();
	for (int i = 1; i < testLen/0x100; ++i) {
		w = MGF1(h, { 1,2,3,4,5,6,7,8,9,10 }, i);
		truncTest = truncTest && (memcmp(&v[0], &w[0], i) == 0);
	}
	for (int i = testLen / 0x100; i < testLen; i+=0x50) {
		w = MGF1(h, { 1,2,3,4,5,6,7,8,9,10 }, i);
		truncTest = truncTest && (memcmp(&v[0], &w[0], i) == 0);
	}
	std::cout << "MGF1 truncation test ";
	if (truncTest)
		std::cout << "successful";
	else
		std::cout << "failed";
	std::cout << std::endl;
}

charBuf stringToBuffer(const std::string& str) {
	charBuf ret(str.length());
	std::copy(str.begin(), str.end(), ret.begin());
	return ret;
}

int testRsaOaep() {
	auto pk = newRsaPrivateKey(2048);
	std::cout << "N: " << pk.N << std::endl;
	std::cout << "e: " << pk.e << std::endl;
	std::cout << "d: " << pk.d << std::endl;
	std::cout << "p: " << pk.p << std::endl;
	std::cout << "q: " << pk.q << std::endl;
	std::cout << "dp: " << pk.dp << std::endl;
	std::cout << "dq: " << pk.dq << std::endl;
	std::cout << "qinv: " << pk.qinv << std::endl << std::endl;
	RsaOaepDecryptor key(pk, mgf1sha1, std::make_shared<Sha1Class>());
	bool success = true;
	for (size_t l = 0x10; l <= 0xd0; l += 0x10) {
		std::cout << "Message size: " << l << std::endl;
		for (int i = 0; i < 200; ++i) {
			charBuf M = getRandomBuffer(l);
			charBuf C;
			charBuf Mprime;
			C = key.encrypt(M);
			Mprime = key.decrypt(C);
			std::cout << std::hex << "M:  " << vectorToMpzClass(M) << std::endl << "M': " << vectorToMpzClass(Mprime) << std::endl;
			bool roundSuccess = (M == Mprime);
			success = success && roundSuccess;
			if (roundSuccess)
				std::cout << "Success!" << std::endl;
			else
				std::cout << "Failure!" << std::endl;
		}
		std::cout << std::endl;
	}
	if (success) {
		std::cout << "All succeded!" << std::endl;
		return 0;
	}
	else {
		std::cout << "Some failures." << std::endl;
		return 1;
	}
}

int main()
{
	testRsaOaep();
	return 0;
}

