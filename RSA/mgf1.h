#pragma once
#include "RsaDecryptor.h"

//this function XORs its output with the output buffer, it does not directly write it
charBuf::iterator MGF1(hashPtr hash, charBuf::const_iterator begin, charBuf::const_iterator end, charBuf::iterator d_begin, size_t maskLen);

extern mgfPtr mgf1sha1;

charBuf MGF1(hashPtr hash, const charBuf& mgfSeed, size_t maskLen);