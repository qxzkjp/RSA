#pragma once

#ifndef BYTE
#define BYTE uint8_t
#endif
#include <vector>
#include <string>

class Buffer
{
public:
	Buffer(size_t n = 0);
	Buffer(std::string str);
	Buffer(const Buffer& buf);
	Buffer(Buffer&& buf) noexcept;
	Buffer& operator=(const Buffer& buf);
	~Buffer();
	BYTE* raw();
	BYTE const* raw() const;
	size_t size() const;
	BYTE& operator[](size_t i);
	BYTE const& operator[](size_t i) const;
	bool operator==(const Buffer& buf) const;
	bool operator==(const std::vector<char>& v) const;
protected:
	BYTE* _data;
	size_t _sz;
private:
	void updateData(BYTE* ptr = nullptr);
};

#ifdef __GNU_MP__
//integers are encoded MSB first, per PKCS#1
Buffer mpzClassToBuffer(mpz_class n);
mpz_class bufferToMpzClass(Buffer buf);
#endif
