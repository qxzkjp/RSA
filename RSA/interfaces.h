#pragma once
#include <vector>
#include <memory>

/*Interfaces should *always* be inherited as virtual public.
**It may not always be stricctly neccesary, but having a simple rule
**prevents mistakes, and ensures that any classes implementing
**these interfaces can be inherited from without problems, eg
**an Encryptor that has a HashFunction as its base class.
**ALL INTERFACES MUST HAVE VIRTUAL DESTRUCTORS!
*/

class CipherBase
{
public:
	virtual std::vector<char> exportKey() = 0;
	virtual void importKey(std::vector<char> buf) = 0;
	virtual ~CipherBase() {};
};

class HashFunction
{
public:
	virtual void reset() = 0;
	virtual std::istream& addData(std::istream& inbuf) = 0;
	virtual void addData(std::vector<char>::const_iterator begin, std::vector<char>::const_iterator end) = 0;
	virtual std::vector<char> finalise() = 0;
	virtual void finalise(std::vector<char>::iterator it) = 0;
	virtual size_t length() = 0;
	virtual std::shared_ptr<HashFunction> clone() = 0;
	virtual ~HashFunction() {};
};

//HashFunction::~HashFunction(){}

class Encryptor : virtual public CipherBase
{
public:
	virtual std::vector<char> encrypt(const std::vector<char>& v) = 0;
	virtual ~Encryptor() {};
};

class TaggedEncryptor : virtual public Encryptor
{
public:
	virtual std::vector<char> encrypt(const std::vector<char>& v, const std::vector<char>& tag) = 0;
	virtual ~TaggedEncryptor() {};
};

class Decryptor : virtual public CipherBase
{
public:
	virtual std::vector<char> decrypt(const std::vector<char>& v) = 0;
	virtual ~Decryptor() {};
	//virtual void generateKey(size_t sz) = 0;
};

class TaggedDecryptor : virtual public Decryptor
{
public:
	virtual std::vector<char> decrypt(const std::vector<char>& v, const std::vector<char>& tag) = 0;
	virtual ~TaggedDecryptor() {};
};

typedef std::shared_ptr<HashFunction> hashPtr;
typedef std::vector<char> charBuf;

inline charBuf doHash(hashPtr hash, charBuf L) {
	hash->reset();
	hash->addData(L.begin(), L.end());
	charBuf lHash = hash->finalise();
	hash->reset();
	return lHash;
}
