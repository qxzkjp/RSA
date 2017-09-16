 // SHA1.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "../RSA/Buffer.h"
#include "../RSA/interfaces.h"
#include "PointedBuffer.h"
#include "Sha1Class.h"

void printVec(std::vector<char> buf, std::ostream& os = std::cout) {
	std::ios::fmtflags flg(os.flags());
	os << std::hex;
	for (int i = 0; i < buf.size(); ++i) {
		if ((buf[i] & 0xF0) == 0)
			os << "0";
		os << (int)(unsigned char)buf[i];
		if (i % 4 == 3)
			os << " ";
	}
	os.flags(flg);
}

Buffer bufFromHexStr(std::string hex){
	if (hex.length() % 2 != 0)
		return Buffer(0);
	Buffer ret(hex.size() / 2);
	for (int i = 0; i < hex.size(); i += 2) {
		std::string sub = hex.substr(i, 2);
		ret[i / 2] = (BYTE)std::strtoul(&sub[0], 0, 16);
	}
	return ret;
}

void printBuffer(Buffer buf) {
	std::ios::fmtflags flg(std::cout.flags());
	std::cout << std::hex;
	for (int i = 0; i < buf.size(); ++i) {
		if (buf[i] < 0x10)
			std::cout << "0";
		std::cout << (int)buf[i];
		if (i % 4 == 3)
			std::cout << " ";
	}
	std::cout.flags(flg);
}

bool testSha1(std::vector<std::vector<char>> msg, Buffer expected, size_t count = 1, std::ostream* os = nullptr) {
	Sha1Class sha;
	for (auto i = msg.begin(); i != msg.end(); ++i) {
		for (size_t j = 0; j < count; ++j) {
			sha.addData(*i);
		}
	}
	std::vector<char> out = sha.finalise();
	if (os) {
		(*os) << "Expected: ";
		printBuffer(expected);
		(*os) << std::endl;
		(*os) << "Actual:   ";
		printVec(out, *os);
		(*os) << std::endl;
	}
	return expected == out;
}

bool testSha1(std::vector<std::shared_ptr<std::istream>> msg, Buffer expected, std::ostream* os = nullptr) {
	Sha1Class sha;
	for (auto i = msg.begin(); i != msg.end(); ++i) {
			sha.addData(**i);
	}
	std::vector<char> out = sha.finalise();
	if (os) {
		(*os) << "Expected: ";
		printBuffer(expected);
		(*os) << std::endl;
		(*os) << "Actual:   ";
		printVec(out, *os);
		(*os) << std::endl;
	}
	return expected == out;
}

bool showSha1Test(std::vector<std::vector<char>> msg, Buffer expected, size_t count = 1) {
	if (testSha1(msg, expected, count, &std::cout)) {
		std::cout << "Success!" << std::endl;
		return true;
	}
	else {
		std::cout << "Failure!" << std::endl;
		return false;
	}
}

bool showSha1Test(std::vector<std::shared_ptr<std::istream>> msg, Buffer expected) {
	if (testSha1(msg, expected, &std::cout)) {
		std::cout << "Success!" << std::endl;
		return true;
	}
	else {
		std::cout << "Failure!" << std::endl;
		return false;
	}
}

struct Sha1TestVector {
	std::vector<std::vector<char>> msg;
	Buffer expected;
	size_t count;
};

struct sha1TestStream {
	std::vector<std::shared_ptr<std::istream>> msg;
	Buffer expected;
};

bool showSha1Test(Sha1TestVector v) {
	return showSha1Test(v.msg, v.expected, v.count);
}

bool showSha1Test(sha1TestStream v) {
	return showSha1Test(v.msg, v.expected);
}

std::shared_ptr<std::stringstream> strptr(const char* str) {
	return std::shared_ptr<std::stringstream>(new std::stringstream(str));
}

std::vector<char> str2vec(std::string str) {
	std::vector<char> v;
	v.resize(str.size());
	if(str.size()>0)
		memcpy(&v[0], &str[0], str.size());
	return v;
}

bool testSha1Clone(Sha1TestVector vec, std::ostream* os = nullptr) {
	Sha1Class sha;
	for (auto i = vec.msg.begin(); i != vec.msg.end(); ++i) {
		for (size_t j = 0; j < vec.count; ++j) {
			sha.addData(*i);
		}
	}
	HashFunction* ptr = sha.clone();
	std::vector<char> out = ptr->finalise();
	if (os) {
		(*os) << "Expected: ";
		printBuffer(vec.expected);
		(*os) << std::endl;
		(*os) << "Actual:   ";
		printVec(out, *os);
		(*os) << std::endl;
	}
	return vec.expected == out;
}

bool showSha1CloneTest(Sha1TestVector vec) {
	if (testSha1Clone(vec, &std::cout)) {
		std::cout << "Success!" << std::endl;
		return true;
	}
	else {
		std::cout << "Failure!" << std::endl;
		return false;
	}
}

int main()
{
	std::vector<Sha1TestVector> vects = {
		{
			{ str2vec("") },
			bufFromHexStr("da39a3ee5e6b4b0d3255bfef95601890afd80709"),
			1
		},
		{
			{ str2vec("abc") },
			bufFromHexStr("a9993e364706816aba3e25717850c26c9cd0d89d"),
			1
		},
		{
			{ str2vec("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") },
			bufFromHexStr("84983e441c3bd26ebaae4aa1f95129e5e54670f1"),
			1
		},
		{
			{ str2vec("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu") },
			bufFromHexStr("a49b2446a02c645bf419f995b67091253a04a259"),
			1
		},
		{
			{ str2vec("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghij"),
			str2vec("klmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu") },
			bufFromHexStr("a49b2446a02c645bf419f995b67091253a04a259"),
			1
		},
		{
			{ str2vec("a") },
			bufFromHexStr("34aa973cd4c4daa4f61eeb2bdbad27316534016f"),
			1000000
		},
	};
	std::vector<sha1TestStream> streams = {
		{
			{ strptr("") },
			bufFromHexStr("da39a3ee5e6b4b0d3255bfef95601890afd80709")
		},
		{
			{ strptr("abc") },
			bufFromHexStr("a9993e364706816aba3e25717850c26c9cd0d89d")
		},
		{
			{ strptr("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") },
			bufFromHexStr("84983e441c3bd26ebaae4aa1f95129e5e54670f1")
		},
		{
			{ strptr("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu") },
			bufFromHexStr("a49b2446a02c645bf419f995b67091253a04a259")
		},
		{
			{ strptr("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghij"),
			strptr("klmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu") },
			bufFromHexStr("a49b2446a02c645bf419f995b67091253a04a259")
		},
	};
	bool success = true;
	std::cout << "Testing hashing from vectors..." << std::endl;
	for (auto i = vects.begin(); i != vects.end(); ++i)
		success = success && showSha1Test(*i);
	std::cout << std::endl << "Testing hashing from streams..." << std::endl;
	for (auto i = streams.begin(); i != streams.end(); ++i)
		success = success && showSha1Test(*i);
	std::cout << std::endl << "Testing hash object cloning..." << std::endl;
	for (auto i = vects.begin(); i != vects.end(); ++i)
		success = success && showSha1CloneTest(*i);
	if (success)
		std::cout << std::endl << "All succeeded!";
	else
		std::cout << std::endl << "Some failures.";
	std::cout << std::endl;
	system("pause");
    return 0;
}
