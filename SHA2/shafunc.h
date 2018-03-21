#ifndef SHAFUNC_H
#define SHAFUNC_H
#include <stdint.h>
#include <string>

uint32_t getword(uint8_t* buf);
void pad512(const uint8_t* msg, size_t len, uint8_t* &buf, size_t& newlen);
void testpadding(uint8_t* msg, size_t len);
inline uint32_t rotr(uint32_t x, size_t shft);
inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z);
inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z);
inline uint32_t capsig0(uint32_t x);
inline uint32_t capsig1(uint32_t x);
inline uint32_t sig0(uint32_t x);
inline uint32_t sig1(uint32_t x);
std::string SHA256(const uint8_t* msg, size_t len);
#endif //SHAFUNC_H