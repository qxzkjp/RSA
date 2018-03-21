#ifndef WORDBUF_H
#define WORDBUF_H
#include <stdint.h>

//Turns a 4-byte buffer into an unsigned integer
uint32_t getword(uint8_t const * buf);

//Turns an unsigned integer into a 4-byte buffer
void writeword(uint32_t wrd, uint8_t * buf);

//Turns an 8-byte buffer into an unsigned 64-bit integer
uint64_t getword64(uint8_t const * buf);

//Turns an unsigned 64-bit integer into an 8-byte buffer
void writeword64(uint64_t wrd, uint8_t * buf);
#endif //WORDBUF_H