#ifndef SHACLASS_H
#define SHACLASS_H
#include <ctime>
#include "../RSA/interfaces.h"

class SHA1_class : public HashFunction
{
public:
	SHA1_class();
	virtual void addData(std::vector<char>::const_iterator begin, std::vector<char>::const_iterator end);
	virtual std::istream& addData(std::istream& inbuf);
	std::vector<char> finalise() const;
	virtual void finalise(std::vector<char>::iterator it) const;
	size_t get_hash_length() const;
	size_t get_block_length() const;
	size_t length() const {
		return get_hash_length();
	}
	virtual size_t blockLength() const {
		return get_block_length();
	}
	virtual void reset();
	virtual std::shared_ptr<HashFunction> clone() const;
private:
	static void compress(uint32_t IV[5], uint8_t const * const data_in);// const;
	void add_buffer();
	uint64_t _length;
	size_t ctr;
	uint32_t h[5];
	uint8_t buffer[64];
};

class SHA256_class : public HashFunction
{
public:
	SHA256_class();
	virtual std::istream& addData(std::istream& inbuf);
	virtual void addData(std::vector<char>::const_iterator begin, std::vector<char>::const_iterator end);
	virtual std::vector<char> finalise() const;
	virtual void finalise(std::vector<char>::iterator it) const;
	virtual size_t get_hash_length() const;
	size_t get_block_length() const;
	virtual size_t length() const {
		return get_hash_length();
	}
	virtual size_t blockLength() const {
		return get_block_length();
	}
	virtual void reset();
	virtual std::shared_ptr<HashFunction> clone() const;
protected:
	uint32_t h[8];
private:
	static void compress(uint32_t IV[8], uint8_t const * const data_in);// const;
	void add_buffer();
	uint64_t _length;
	size_t ctr; //where are we in the buffer?
	uint8_t buffer[64];
};

class SHA224_class : public SHA256_class
{
public:
	SHA224_class();
	virtual charBuf finalise() const;
	virtual void finalise(std::vector<char>::iterator it) const;
	size_t get_hash_length() const;
	virtual void reset();
	virtual std::shared_ptr<HashFunction> clone() const;
};

struct ctr128
{
	uint64_t high;
	uint64_t low;
};

ctr128& operator+=(ctr128& lhs, const ctr128& rhs);
ctr128& operator+=(ctr128& lhs, const uint64_t& rhs);
ctr128 operator+(ctr128 lhs, const ctr128& rhs);
ctr128 operator+(ctr128 lhs, const uint64_t& rhs);
ctr128& operator++(ctr128& lhs);
ctr128 operator++(ctr128& lhs, int);

class SHA512_class : public HashFunction
{
public:
	SHA512_class();
	virtual std::vector<char> finalise() const;
	virtual void finalise(std::vector<char>::iterator it) const;
	virtual std::istream& addData(std::istream& inbuf);
	virtual void addData(std::vector<char>::const_iterator begin, std::vector<char>::const_iterator end);
	virtual size_t get_hash_length() const;
	virtual size_t length() const {
		return get_hash_length();
	}
	size_t get_block_length() const;
	virtual size_t blockLength() const {
		return get_block_length();
	}
	virtual void reset();
	virtual std::shared_ptr<HashFunction> clone() const;
protected:
	uint64_t h[8];
private:
	static void compress(uint64_t IV[8], uint8_t const * const data_in);// const;
	void add_buffer();
	ctr128 _length;
	size_t ctr; //where are we in the buffer?
	uint8_t buffer[128];
};

class SHA384_class : public SHA512_class
{
public:
	SHA384_class();
	virtual std::vector<char> finalise() const;
	virtual void finalise(std::vector<char>::iterator it) const;
	size_t get_hash_length() const;
	virtual void reset();
	virtual std::shared_ptr<HashFunction> clone() const;
};


struct totp_return
{
	uint32_t code;
	size_t timestep;
};

uint32_t HOTP(const charBuf& K, uint64_t ctr, size_t digits = 6);
totp_return TOTP(const charBuf& K, size_t digits, size_t lookahead = 0, std::time_t X = 30, std::time_t epoch = 0);

#endif //SHACLASS_H