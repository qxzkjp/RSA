#pragma once
template<class Hash>
charBuf HMAC(charBuf K, const charBuf& M)
{
	const uint8_t ipad = 0x36;
	const uint8_t opad = 0x5C;
	Hash hash;
	size_t B = hash.blockLength();
	//size_t L = hash->get_hash_length();
	charBuf tmp;
	charBuf ret;

	//if the key is too long, replace it with its hash
	if (K.size()>B)
	{
		hash.addData(K.begin(), K.end());
		K = hash.finalise();
		hash.reset();
	}

	//pad K to block size with zeroes
	K.resize(B, 0);
	//and then XOR it with ipad
	for (auto it = K.begin(); it != K.end(); ++it)
		(*it) ^= ipad;
	//now hash K xor ipad, M
	hash.addData(K.begin(), K.end());
	hash.addData(M.begin(), M.end());
	tmp = hash.finalise();
	hash.reset();

	//now we unxor ipad from K, then xor it with opad
	for (auto it = K.begin(); it != K.end(); ++it)
		(*it) ^= ipad^opad;
	//then hash the first hash prepended with k xor opad
	hash.addData(K.begin(), K.end());
	hash.addData(tmp.begin(), tmp.end());
	//which gives us our final result
	ret = hash.finalise();
	return ret;
}
