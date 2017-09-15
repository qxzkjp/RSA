#include "stdafx.h"

#include "Buffer.h"

Buffer::Buffer(size_t n )
{
	_sz = n;
	updateData();
}
Buffer::Buffer(std::string str) {
	_sz = str.size();
	updateData((BYTE*)&str[0]);
}
Buffer::Buffer(const Buffer& buf) {
	_sz = buf._sz;
	updateData(buf._data);
}
Buffer::Buffer(Buffer&& buf) noexcept : _sz(buf._sz), _data(buf._data) {
	buf._sz = 0;
	buf._data = nullptr;
}
Buffer& Buffer::operator=(const Buffer& buf) {
	if (this != &buf) {
		_sz = buf._sz;
		if (_data) //if data isn't a null pointer, free it
			delete[] _data;
		updateData(buf._data);
	}
	return *this;
}
Buffer::~Buffer() {
	if (_sz != 0)
		delete[] _data;
}
BYTE* Buffer::raw() {
	return _data;
}
BYTE const* Buffer::raw() const {
	return _data;
}
size_t Buffer::size() const {
	return _sz;
}
BYTE& Buffer::operator[](size_t i) {
	return _data[i];
}
BYTE const& Buffer::operator[](size_t i) const {
	return _data[i];
}
bool Buffer::operator==(const Buffer& buf) const {
	if (_sz != buf._sz)
		return false;
	if (memcmp(_data, buf._data, _sz) == 0)
		return true;
	return false;
}

bool Buffer::operator==(const std::vector<char>& v) const {
	if (_sz != v.size())
		return false;
	if (memcmp(_data, &v[0], _sz) == 0)
		return true;
	return false;
}

void Buffer::updateData(BYTE* ptr ) {
	if (_sz > 0) {
		_data = new BYTE[_sz];
		if (ptr)
			memcpy(_data, ptr, _sz);
	}
	else {
		_data = nullptr;
	}
}

#ifdef __GNU_MP__
//integers are encoded MSB first, per PKCS#1
Buffer mpzClassToBuffer(mpz_class n) {
	size_t numBytes = (mpz_sizeinbase(n.get_mpz_t(), 2) + 7) >> 3;
	Buffer ret(numBytes);
	mpz_export((void*)ret.raw(), NULL, 1, 1, -1, 0, n.get_mpz_t());
	return ret;
}

mpz_class bufferToMpzClass(Buffer buf) {
	mpz_class p;
	mpz_import(p.get_mpz_t(), buf.size(), 1, 1, -1, 0, (void*)buf.raw());
	return p;
}

#endif