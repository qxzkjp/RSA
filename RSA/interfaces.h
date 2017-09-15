#pragma once
#include <vector>

class HashFunction
{
public:
	virtual void reset() = 0;
	virtual std::istream& addData(std::istream& inbuf) = 0;
	virtual void addData(const std::vector<char>& v) = 0;
	virtual std::vector<char> finalise() = 0;
};

class AsymmetricEncryptor
{
public:
	virtual virtual std::vector<char> encrypt(Buffer buf) = 0;
	virtual virtual std::vector<char> exportKey() = 0;
	virtual void importKey(Buffer buf) = 0;
};

class AsymmetricDecryptor : public AsymmetricEncryptor
{
public:
	virtual virtual std::vector<char> decrypt(Buffer buf) = 0;
	virtual void generateKey(size_t sz) = 0;
};

/*
class symmetricCypher
{
	virtual Buffer encrypt(Buffer buf) = 0;
	virtual Buffer decrypt(Buffer buf) = 0;
};
*/