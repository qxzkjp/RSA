#pragma once
#include <vector>

/*Interfaces should *always* be inherited as virtual public.
**It may not always be stricctly neccesary, but having a simple rule
**prevents mistakes, and ensures that any classes implementing
**these interfaces can be inherited from without problems, eg
**an Encryptor that has a HashFunction as its base class
*/

class CipherBase
{
public:
	virtual std::vector<char> exportKey() = 0;
	virtual void importKey(std::vector<char> buf) = 0;
};

class HashFunction
{
public:
	virtual void reset() = 0;
	virtual std::istream& addData(std::istream& inbuf) = 0;
	virtual void addData(const std::vector<char>& v) = 0;
	virtual std::vector<char> finalise() = 0;
	virtual void finalise(std::vector<char>::iterator it) = 0;
	virtual size_t length() = 0;
	virtual HashFunction* clone() = 0;
};

class Encryptor : virtual public CipherBase
{
public:
	virtual std::vector<char> encrypt(const std::vector<char>& v) = 0;
};

class Decryptor : virtual public CipherBase
{
public:
	virtual std::vector<char> decrypt(const std::vector<char>& v) = 0;
	//virtual void generateKey(size_t sz) = 0;
};
