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
	virtual std::vector<char> finalise() const = 0;
	virtual void finalise(std::vector<char>::iterator it) const = 0;
	virtual size_t length() const = 0;
	virtual size_t blockLength() const = 0;
	virtual std::shared_ptr<HashFunction> clone() const = 0;
	virtual ~HashFunction() {};
};

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

class KeyAgreement : virtual public CipherBase
{
public:
	virtual std::vector<char> getPublic() const = 0;
	virtual std::vector<char> agreeKey(std::vector<char> otherPublic) const = 0;
	virtual ~KeyAgreement() {};
};


//sign() takes a vector because it may need to read the message several times
//sign with no arguments gives the result of signing the message pass()-ed through
//will return an empty buffer or perhaps throw an exception if there is no signature ready
//a buffer passed to pass() will be read once, and the return value indicates whether
//the Signer is ready to output a signature.
//NOTE: the exact same file/buffer must be fed into pass both times or the output is gibberish
class Signer : virtual public CipherBase
{
public:
	virtual std::vector<char> sign(std::vector<char>::const_iterator begin, std::vector<char>::const_iterator end) = 0;
	virtual bool pass(std::istream& msg) = 0;
	virtual std::vector<char> sign() = 0;
	virtual ~Signer() {};
};

class Verifier : virtual public CipherBase
{
public:
	virtual bool verify(std::istream& msg, const std::vector<char>& sig) = 0;
	virtual ~Verifier() {};
};

typedef std::shared_ptr<HashFunction> hashPtr;
typedef std::shared_ptr<Verifier> verifyPtr;
typedef std::vector<char> charBuf;
typedef charBuf::iterator(*mgfPtr)(charBuf::const_iterator begin, charBuf::const_iterator end, charBuf::iterator d_begin, size_t maskLen);
typedef charBuf(*hashFunc)(std::istream&);

inline charBuf doHash(hashPtr hash, charBuf L) {
	hash->reset();
	hash->addData(L.begin(), L.end());
	charBuf lHash = hash->finalise();
	hash->reset();
	return lHash;
}

template<class Hash>
inline charBuf doHash(charBuf L) {
	Hash hash{};
	hash.addData(L.begin(), L.end());
	charBuf lHash = hash.finalise();
	return lHash;
}
