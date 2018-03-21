// RSA.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <memory>
#include <fstream>
#include <sstream>
#include "randomNumbers.h"
#include "mpzConvert.h"
#include "RsaDecryptor.h"
#include "../SHA1/Sha1Class.h"
#include "mgf1.h"


void printVec(charBuf buf, std::ostream& os = std::cout, bool wrap=true) {
	std::ios::fmtflags flg(os.flags());
	os << std::hex;
	for (int i = 0; i < buf.size(); ++i) {
		if ((buf[i] & 0xF0) == 0)
			os << "0";
		os << (int)(unsigned char)buf[i];
		if (wrap && i % 4 == 3 && i % 32 != 31)
			os << " ";
		if (wrap && (i % 32 == 31))
			os << std::endl;
	}
	os.flags(flg);
}

std::string formatVec(charBuf buf) {
	std::stringstream ss;
	printVec(buf, ss, false);
	return ss.str();
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
	charBuf v = MGF1<Sha1Class>({ 1,2,3,4,5,6,7,8,9,10 }, testLen);
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
	for (int i = 1; i < testLen/0x100; ++i) {
		w = MGF1<Sha1Class>({ 1,2,3,4,5,6,7,8,9,10 }, i);
		truncTest = truncTest && (memcmp(&v[0], &w[0], i) == 0);
	}
	for (int i = testLen / 0x100; i < testLen; i+=0x50) {
		w = MGF1<Sha1Class>({ 1,2,3,4,5,6,7,8,9,10 }, i);
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

int testRsaOaep(std::string filename="rsaLog.txt") {
	std::fstream fs(filename, std::ios::out | std::ios::app);
	if (!fs)
		std::cerr << "Could not open log file" << std::endl;
	std::ostringstream ss;
	auto pk = newRsaPrivateKey(2048);
	ss << "N:\t\t" << pk.N << std::endl;
	ss << "e:\t\t" << pk.e << std::endl;
	ss << "d:\t\t" << pk.d << std::endl;
	ss << "p:\t\t" << pk.p << std::endl;
	ss << "q:\t\t" << pk.q << std::endl;
	ss << "dp:\t\t" << pk.dp << std::endl;
	ss << "dq:\t\t" << pk.dq << std::endl;
	ss << "qinv:\t" << pk.qinv << std::endl << std::endl;
	std::cout << ss.str();
	fs << ss.str();
	ss.str("");
	ss.clear();
	RsaOaepDecryptor<MGF1_class<Sha1Class>, Sha1Class> key(pk);
	bool success = true;
	for (size_t l = 0x10; l <= 0xd0; l += 0x10) {
		std::cout << "Message size: " << l << std::endl;
		for (int i = 0; i < 200; ++i) {
			charBuf M = getRandomBuffer(l);
			charBuf C;
			charBuf Mprime;
			C = key.encrypt(M);
			Mprime = key.decrypt(C);
			bool roundSuccess = (M == Mprime);
			success = success && roundSuccess;
			if (roundSuccess) {
				std::cout << std::hex << "M:\t" << vectorToMpzClass(M) << std::endl << "M':\t" << vectorToMpzClass(Mprime) << std::endl;
				std::cout << "Success!" << std::endl;
			}
			else {
				ss << std::hex << "M:\t\t" << vectorToMpzClass(M) << std::endl;
#ifdef _DEBUG
				ss << "Seed:\t" << formatVec(key.getLastSeed()) << std::endl;
#endif
				ss << std::hex << "C:\t\t" << vectorToMpzClass(C) << std::endl;
				ss << "M':\t\t" << vectorToMpzClass(Mprime) << std::endl;
				std::cout << ss.str();
				fs << ss.str() << std::endl;
				ss.str("");
				ss.clear();
				std::cout << "Failure!" << std::endl;
			}
		}
		std::cout << std::endl;
	}
	fs << "-----" << std::endl << std::endl;
	if (success) {
		std::cout << "All succeded!" << std::endl;
		return 0;
	}
	else {
		std::cout << "Some failures." << std::endl;
		return 1;
	}
}

std::vector<char> hexStrToVec(std::string s) {
	std::stringstream ss;
	char c;
	std::vector<char> ret;
	for (size_t i = 0; i < s.size(); i += 2) {
		c = (char)stoi(s.substr(i, 2), nullptr, 16);
		ret.push_back(c);
	}
	return ret;
}

bool testSpecificCase(
	std::string nStr,
	std::string eStr,
	std::string dStr,
	std::string pStr,
	std::string qStr,
	std::string dpStr,
	std::string dqStr,
	std::string qInvStr,
	std::string seed,
	std::string msg
) {
	rsaPrivateKey pk = {
		mpz_class(nStr),
		mpz_class(eStr),
		mpz_class(dStr),
		mpz_class(pStr),
		mpz_class(qStr),
		mpz_class(dpStr),
		mpz_class(dqStr),
		mpz_class(qInvStr) };
	RsaOaepDecryptor<MGF1_class<Sha1Class>, Sha1Class> dec(pk);
	charBuf M = hexStrToVec(msg);
	dec.setNextSeed(hexStrToVec(seed));
	charBuf C = dec.encrypt(M);
	charBuf mPrime = dec.decrypt(C);
	return (M == mPrime);
}

int main()
{
	return testRsaOaep();
}

