// ASN1.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "../RSA/interfaces.h"
#include "ASN1.h"

using std::cout;
using std::cin;
using std::cerr;
using std::endl;
using std::vector;
using std::ios;
using std::ifstream;
using std::fstream;
using std::istream;
using std::make_shared;
using std::shared_ptr;

void appendSeptets(std::ostream& os, size_t n) {
	const size_t bitness = sizeof(size_t)*CHAR_BIT;
	static_assert(bitness == 64, "this algorithm assumes a 64-bit system");
	if (n == 0) {
		os << '\0';
		return;
	}
	if ((n&(1LL << (bitness - 1))) != 0) {//check high bit
		os << ((char)(unsigned char)0x81); //we set the high bit to signal there is more
		n <<= 1; //throw away high bit
	}
	else {//if there is no high bit, we have leading zeroes, and may have to throw away the first few septets
		n <<= 1; //throw away high bit
		if (n != 0)  //if we still have bits left, they'll be shifted into top septet
			while ((n&(0xF7LL << 56)) == 0) //while there is nothing in the top septet
				n <<= 7; //we throw away the top 7 bits
	}
	//once high bit is dealt with, we have 63 remaining bits, and 63=7*9
	//so we can take 7 bits at a time until we get to the end of the number
	//of course, some septets may have already been discarded as leading zeroes
	while (n > 0) {
		char tmp = n >> 57; //top 7 bits
		if ((n & 0x01FFFFFFFFFFFFFFLL) != 0) //if there are more than 7 bits left
			tmp |= 0x80; //we set the high bit to signal we are not finished
		os << tmp;
		n <<= 7;
	}
}

void appendSeptets(vector<char>& v, size_t n) {
	if (n == 0) {
		v.push_back(0);
		return;
	}
	const size_t bitness = sizeof(size_t)*CHAR_BIT;
	static_assert(bitness == 64, "this algorithm assumes a 64-bit system");
	if ((n&(1LL << (bitness - 1))) != 0) {//check high bit
		v.push_back((char)(unsigned char)0x81); //we set the high bit to signal there is more
		n <<= 1; //throw away high bit
	}
	else {//if there is no high bit, we have leading zeroes, and may have to throw away the first few septets
		n <<= 1; //throw away high bit
		if (n != 0)  //if we still have bits left, they'll be shifted into top septet
			while ((n&(0xF7LL << 56)) == 0) //while there is nothing in the top septet
				n <<= 7; //we throw away the top 7 bits
	}
	//once high bit is dealt with, we have 63 remaining bits, and 63=7*9
	//so we can take 7 bits at a time until we get to the end of the number
	//of course, some septets may have already been discarded as leading zeroes
	while (n > 0) {
		char tmp = n >> 57; //top 7 bits
		if ((n & 0x01FFFFFFFFFFFFFFLL) != 0) //if there are more than 7 bits left
			tmp |= 0x80; //we set the high bit to signal we are not finished
		v.push_back(tmp);
		n <<= 7;
	}
}

size_t readSeptets(std::istream& is, size_t& bytesRead) {
	const size_t bitness = sizeof(size_t)*CHAR_BIT;
	static_assert(bitness == 64, "this algorithm assumes a 64-bit system");
	bool flg = true; //this will be set to false when the high bit of a read byte is 0
	size_t ret = 0;
	bytesRead = 0;
	char next;
	while (flg) {
		++bytesRead;
		//if we have more than 64 bits of length
		if (bytesRead == 10 ||
			(bytesRead == 9
				&& (ret >> 57) > 1
				)) {
			cerr << "readSeptets: tag cannot fit in size_t" << endl;
			throw SizeException();
		}
		is.read(&next, 1); //read next byte
		if (!is) {
			cerr << "readSeptets: unexpected EOF while reading tag" << endl;
			throw EOFexception();
		}
		flg = next & 0x80; //get high bit
		next &= 0x7F; //get rid of high bit
		ret <<= 7; //make room for 7 bits at the bottom of the output
		ret += next; //next is def. positive because high bit is clear
	}
	return ret;
}

size_t readSeptets(std::istream& is) {
	size_t bytes = 0;
	return readSeptets(is, bytes);
}

std::string stringFromVec(const vector<char>& v) {
	if (v.size() > 0)
		return std::string(&v[0], v.size());
	else
		return std::string();
}

vector<size_t> parseOID(std::istream& is, size_t len) {
	vector<size_t> ret;
	if (len == 0)
		return vector<size_t>(0);
	char tmp;
	is.read(&tmp, 1);
	if (!is) {
		cerr << "parseOID: unexpected EOF while reading segment" << endl;
		throw EOFexception();
	}
	//some weird decoding voodoo for the first two segments
	//for 0-39 seg 1 is 0, seg 2 is 0-39
	//for 40-79 seg1 is 1, seg 2 is 0-39
	//80+, seg 1 is 2, seg 2 is (the value) - 80
	if ((unsigned char)tmp / 40 < 2) {
		ret.push_back((unsigned char)tmp / 40);
		ret.push_back((unsigned char)tmp % 40);
	}
	else {
		ret.push_back(2);
		ret.push_back((unsigned char)tmp - 80);
	}
	size_t nextSeg = 0;
	size_t bytesRead = 1;
	while (bytesRead < len) {
		size_t segBytes;
		ret.push_back(readSeptets(is, segBytes));
		bytesRead += segBytes;
	}
	return ret;
}

vector<size_t> parseOID(const vector<char>& v) {
	std::stringstream ss(stringFromVec(v));
	return parseOID(ss, v.size());
}

vector<char> stringToVec(const std::string& s) {
	vector<char> ret(s.size());
	std::copy(s.begin(), s.end(), ret.begin());
	return ret;
}

AsnObject makeNull() {
	return AsnObject(0, 5, 2, vector<char>(0));
}

AsnObject getConstructedObject(istream& is, char cls, size_t tag, size_t preLength, size_t length) {
	//TODO: inmplement this function
	size_t conLeng = 0;
	vector<AsnObject> cmpts;
	while (conLeng < length) {
		cmpts.push_back(parseObject(is));
		conLeng += cmpts.back().rawLength();
	}
	return AsnObject(cls, tag, preLength, cmpts);
}

AsnObject getPrimitiveObject(istream& is, char cls, size_t tag, size_t preLength, size_t length) {
	//TODO: inmplement this function
	vector<char> buffer(length);
	if (length != 0)
		is.read(&buffer[0], length);
	if (!is) {
		cerr << "getPrimitiveObject: unexpected EOF" << endl;
		return makeNull();
	}
	return AsnObject(cls, tag, preLength, buffer);
}

AsnObject parseObject(istream& is) {
	vector<char> buffer(1);
	size_t preLength = 2; //size of tag+header; always at least two
	is.read(&buffer[0], 1);
	if (!is) {
		cerr << "parseObject: missing tag byte" << endl;
		return makeNull();
	}
	char cls = (buffer[0] & 0xc0) >> 6;
	cls &= 0x03;//clear any sign-extended bits
	bool constructed = buffer[0] & 0x20;
	char lowTag = buffer[0] & 0x1F;
	size_t tag;
	size_t length = 0;
	if (lowTag == 0x1F) { //if all 5 low bits are set
		size_t bytesRead;
		tag = readSeptets(is, bytesRead);
		preLength += bytesRead;
	}
	else {
		tag = lowTag;
	}
	is.read(&buffer[0], 1);
	if (!is) {
		cerr << "parseObject: length byte missing" << endl;
		return makeNull();
	}
	if (buffer[0] & 0x80) {
		buffer[0] &= 0x7F;
		if (buffer[0] == 0) {
			cerr << "parseObject: cannot handle indeterminate length" << endl;
			return makeNull();
		}
		if (buffer[0] > 8) {
			cerr << "parseObject: length cannot fit in size_t" << endl;
			return makeNull();
		}
		preLength += (unsigned char)buffer[0]; //we had already allocated one byte for length in the preSize
		buffer.resize(buffer[0]);
		is.read(&buffer[0], buffer.size());
		if (!is) {
			cerr << "parseObject: unexpected EOF while reading length" << endl;
			return makeNull();
		}
		for (int i = 0; i < buffer.size(); ++i) {
			length += (size_t)(unsigned char)buffer[i] << ((buffer.size()-1-i) * 8); //these casts are neccesary because char is signed
		}
	}
	else {
		length = buffer[0];
	}
	if (constructed) {
		return getConstructedObject(is, cls, tag, preLength, length);
	}
	else {
		return getPrimitiveObject(is, cls, tag, preLength, length);
	}
}

std::string oidtoString(const vector<char>& v) {
	vector<size_t> segs = parseOID(v);
	std::stringstream ss;
	for (size_t i = 0; i < segs.size() - 1; ++i) {
		ss << segs[i] << ".";
	}
	ss << segs.back();
	return ss.str();
}

namespace tagNum {
	const char boolean = 1;
	const char integer = 2;
	const char bitString = 3;
	const char octetString = 4;
	const char null = 5;
	const char oid = 6;
	const char utf8String = 12;
	const char sequence = 16;
	const char set = 17;
	const char printableString = 19;
	const char t61String = 20;
	const char IA5String = 22;
	const char utcTime = 23;
	const char universalString = 28;
	const char bmpString = 30;
}

namespace tagClass {
	const char universal = 0;
	const char application = 1;
	const char contextSpecific = 2;
	const char priv = 3;
}

void printAsnObject(AsnObject obj, size_t depth) {
	for (int i = 0; i < depth; ++i)
		cout << "\t";
	bool knownTag = false;
	if (obj.getClass() == 0) {
		knownTag = true;
		if (obj.getTag() == 1)
			cout << "BOOLEAN";
		else if (obj.getTag() == 2)
			cout << "INTEGER";
		else if (obj.getTag() == 3)
			cout << "BIT-STRING";
		else if (obj.getTag() == 4)
			cout << "OCTET-STRING";
		else if (obj.getTag() == 5)
			cout << "NULL";
		else if (obj.getTag() == 6)
			cout << "OBJECT-IDENTIFIER";
		else if (obj.getTag() == 12)
			cout << "UTF8STRING";
		else if (obj.getTag() == 16)
			cout << "SEQUENCE";
		else if (obj.getTag() == 17)
			cout << "SET";
		else if (obj.getTag() == 19)
			cout << "PRINTABLESTRING";
		else if (obj.getTag() == 20)
			cout << "T61STRING";
		else if (obj.getTag() == 22)
			cout << "IA5STRING";
		else if (obj.getTag() == 23)
			cout << "UTCTIME";
		else if (obj.getTag() == 28)
			cout << "UNIVERSALSTRING";
		else if (obj.getTag() == 30)
			cout << "BMPSTRING";
		else
			knownTag = false;
	}
	if (!knownTag) {
		if (obj.getClass() == 0)
			cout << "UNIVERSAL";
		else if (obj.getClass() == 1)
			cout << "APPLICATION";
		else if (obj.getClass() == 2)
			cout << "CONSTEXT-SPECIFIC";
		else if (obj.getClass() == 3)
			cout << "PRIVATE";
		cout << " " << obj.getTag();
	}
	cout << ", size " << obj.length() << endl;
	//print values for certain universal types
	if (obj.getClass() == 0) {
		std::string cont;
		if (obj.getTag() == 1) {//boolean
			if (obj.contents().size() > 0) {
				if (obj.contents()[0] == 0)
					cont = "FALSE";
				else
					cont = "TRUE";
			}
		}
		else if (obj.getTag() == 6) {//OID
			cont = oidtoString(obj.contents());
		}
		if (cont.size() != 0) {
			++depth;
			for (int i = 0; i < depth; ++i)
				cout << "\t";
			cout << cont << endl;
		}
	}
	if (obj.isConstructed()) {
		for (AsnObject sub : obj.subObjects()) {
			printAsnObject(sub, depth + 1);
		}
	}
}

void printVect(vector<char> v, std::ostream& os = cout) {
	auto flg = os.flags();
	os << std::hex;
	for (char c : v) {
		unsigned tmp = (unsigned char)c;
		if (tmp < 0x10) {
			os << "0";
		}
		os << tmp << " ";
	}
	os << endl;
}

size_t intFromOctStr(vector<char> v) {
	size_t ret = 0;
	if (v.size() > 8) {
		cerr << "intFromOctStr: integer too big for size_t. Use mpz function instead." << endl;
		throw SizeException();
	}
	for (size_t i = 0; i< v.size(); ++i) {
		ret <<= 8;
		ret += (unsigned char)v[i];
	}
	return ret;
}

bool checkClassAndTag(AsnObject obj, char cls, size_t tag) {
	return (obj.getClass() == cls && obj.getTag() == tag);
}

/*********************************************************************************
** try* and get* functions:                                                     **
** try* functions will attempt to parse a subobject and place it in value,      **
** returning false if it is not found (used for optional/default values).       **
** get* functions attempt to parse a subobject and place it in value, throwing  **
** an ASNexception if it is not found (used for required values).               **
** both kinds of functions take an object and an index for the subobject, and   **
** increment the index if the object is found.                                  **
*********************************************************************************/

bool tryVersion(const AsnObject& obj, size_t& index, char& value) {
	if (obj.numSubObjects() - 1 < index)
		return false;
	const AsnObject& sub = obj.subObjects(index);
	if (!checkClassAndTag(sub, 2, 0)) { //context-specific 0
		return false;
	}
	if (sub.numSubObjects() != 1) {
		return false;
	}
	if (!checkClassAndTag(sub.subObjects(0), 0, 2)) { //integer
		return false;
	}
	size_t ver = intFromOctStr(sub.subObjects(0).contents());
	if (ver > 2 || ver < 0) {
		throw ASNexception();
	}
	value = (char)ver;
	++index;
	return true;
}

//serial is handled like an object string, despite actually being an integer.
//This is because it might be up to 20 bytes in length, and we don't need to do arithmetic on it
void getSerial(const AsnObject& obj, size_t& index, vector<char>& value) {
	if (obj.numSubObjects() - 1 < index)
		throw ASNexception();
	const AsnObject& sub = obj.subObjects(index);
	if (!checkClassAndTag(sub, 0, 2)) //integer
		throw ASNexception();
	if (sub.contents().size() == 0)
		throw ASNexception();
	++index;
	value = sub.contents();
}

ObjectID getOID(const AsnObject& obj, size_t& index) {
	if (obj.numSubObjects() - 1 < index)
		throw ASNexception();
	const AsnObject& sub = obj.subObjects(index);
	if (!checkClassAndTag(sub, tagClass::universal, tagNum::oid)) {
		cerr << "getOID: object is not an OID" << endl;
		throw ASNexception();
	}
	++index;
	return ObjectID(sub.contents());
}

void getOID(const AsnObject& obj, size_t& index, ObjectID& value) {
	value = getOID(obj, index);
}

codedString getString(const AsnObject& obj, size_t& index) {
	codedString value;
	if (obj.numSubObjects() - 1 < index)
		throw ASNexception();
	const AsnObject& sub = obj.subObjects(index);
	if (sub.getClass() != tagClass::universal) {
		cerr << "getString: object is not a string" << endl;
		throw ASNexception();
	}
	codedString str;
	if (sub.getTag() == tagNum::utf8String) {
		value = codedString(sub.contents(), "UTF8");
	}
	else if (sub.getTag() == tagNum::printableString || sub.getTag() == tagNum::IA5String) {
		value = codedString(sub.contents(), "ASCII");
	}
	else if (sub.getTag() == tagNum::bmpString) {
		value = codedString(sub.contents(), "BMP");
	}
	else {
		cerr << "getString: unrecognised encoding" << endl;
		throw EncodingException();
	}
	++index;
	return value;
}

void getString(const AsnObject& obj, size_t& index, codedString& value) {
	value = getString(obj, index);
}

nameElement getNameElement(const AsnObject& obj, size_t& index) {
	if (obj.numSubObjects() - 1 < index)
		throw ASNexception();
	const AsnObject& sub = obj.subObjects(index);
	if (!checkClassAndTag(sub, tagClass::universal, tagNum::sequence)) {
		cerr << "getName: name element is not a sequence" << endl;
		throw ASNexception();
	}
	if (sub.numSubObjects() != 2) {
		cerr << "getName: name element is not a pair" << endl;
		throw ASNexception();
	}
	size_t i = 0;
	ObjectID OID = getOID(sub, i);
	codedString str= getString(sub, i);
	++index;
	return nameElement(OID, str);
}

void getNameElement(const AsnObject& obj, size_t& index, nameElement& value) {
	value = getNameElement(obj, index);
}

subName getSubName(const AsnObject& obj, size_t& index) {
	if (obj.numSubObjects() - 1 < index)
		throw ASNexception();
	const AsnObject& sub = obj.subObjects(index);
	if (!checkClassAndTag(sub, tagClass::universal, tagNum::set)) {
		cerr << "getName: sub-name is not a set" << endl;
		throw ASNexception();
	}
	subName ret;
	size_t i = 0;
	while (i < sub.numSubObjects()) {
		ret.push_back(getNameElement(sub, i));
	}
	++index;
	return ret;
}

void getSubName(const AsnObject& obj, size_t& index, subName& value) {
	value = getSubName(obj,index);
}

void getName(const AsnObject& obj, size_t& index, nameType& value) {
	if (obj.numSubObjects() - 1 < index)
		throw ASNexception();
	const AsnObject& sub = obj.subObjects(index);
	nameType ret;
	if (!checkClassAndTag(sub, tagClass::universal, tagNum::sequence)) {
		cerr << "getName: name is not a sequence" << endl;
		throw ASNexception();
	}
	size_t i = 0;
	while (i < sub.numSubObjects()) {
		ret.push_back(getSubName(sub, i));
	}
	value = ret;
	++index;
}

void getAsnTime(const AsnObject& obj, size_t& index, AsnTime& value) {
	if (obj.numSubObjects() - 1 < index)
		throw ASNexception();
	const AsnObject& sub = obj.subObjects(index);
	if (!checkClassAndTag(sub, 0, 23)) {
		cerr << "getAsnTime: object is not a UTCTime" << endl;
		throw ASNexception();
	}
	const vector<char>& v = sub.contents();
	AsnTime ret;
	size_t pad = 0;
	if (v.back() == 'Z') {
		//ret.tzHrs = 0;
		ret.tzMin = 0;
		pad = 1;
	}
	else {
		cerr << "getAsnTime: non-UTC timezones not currently supported" << endl;
		throw EncodingException();
	}
	if (v.size() - pad >= 10) {
		std::string digits(3, 0);
		digits[0] = v[0];
		digits[1] = v[1];
		ret.year = atoi(&digits[0]);
		digits[0] = v[2];
		digits[1] = v[3];
		ret.month = atoi(&digits[0]);
		digits[0] = v[4];
		digits[1] = v[5];
		ret.day = atoi(&digits[0]);
		digits[0] = v[6];
		digits[1] = v[7];
		ret.hour = atoi(&digits[0]);
		digits[0] = v[8];
		digits[1] = v[9];
		ret.min = atoi(&digits[0]);
		if (v.size() - pad == 12) {
			digits[0] = v[10];
			digits[1] = v[11];
			ret.sec = atoi(&digits[0]);
			ret.hasSeconds = true;
		}
		else {
			ret.sec = 0;
			ret.hasSeconds = false;
		}
	}
	else {
		cerr << "getAsnTime: invalid format" << endl;
		throw EncodingException();
	}
	value = ret;
	++index;
}

void getValidity(const AsnObject& obj, size_t& index, Validity& value) {
	if (obj.numSubObjects() - 1 < index)
		throw ASNexception();
	const AsnObject& sub = obj.subObjects(index);
	Validity ret;
	size_t i = 0;
	getAsnTime(sub, i, ret.begin);
	getAsnTime(sub, i, ret.end);
	value = ret;
	++index;
}

bool tryBitString(const AsnObject& obj, size_t& index, vector<char>& value) {
	if (obj.numSubObjects() - 1 < index)
		return false;
	const AsnObject& sub = obj.subObjects(index);
	if (!checkClassAndTag(sub, tagClass::universal, tagNum::bitString))
		return false;
	value = sub.contents();
	++index;
	return true;
}

//this function only exists to provide code re-use for getIssuerID/getSubjectID
bool tryUniqueID(const AsnObject& obj, size_t& index, vector<char>& value, size_t tag) {
	if (obj.numSubObjects() - 1 < index)
		return false;
	const AsnObject& sub = obj.subObjects(index);
	if (!checkClassAndTag(sub, 2, tag)) //context-specific tag (issuerID/subjectID)
		return false;
	size_t i = 0;
	vector<char> ret;
	tryBitString(sub, index, ret);
	if (ret.size() > 0)
		value = ret;
	else
		return false;
	++index;
	return true;
}

bool tryIssuerID(const AsnObject& obj, size_t& index, vector<char>& value) {
	return (tryUniqueID(obj, index, value, 1));
}

bool trySubjectID(const AsnObject& obj, size_t& index, vector<char>& value) {
	return (tryUniqueID(obj, index, value, 2));
}

//TODO: eliminate this copy
AsnObject getObject(const AsnObject& obj, size_t& index) {
	if (obj.numSubObjects() - 1 < index)
		throw ASNexception();
	const AsnObject& sub = obj.subObjects(index);
	std::stringstream ss(stringFromVec(sub.contents()));
	AsnObject ret = parseObject(ss);
	++index;
	return ret;
}

bool tryBool(const AsnObject& obj, size_t& index, bool& value) {
	if (obj.numSubObjects() - 1 < index)
		return false;
	const AsnObject& sub = obj.subObjects(index);
	if (!checkClassAndTag(sub, tagClass::universal, tagNum::boolean))
		return false;
	if (sub.contents().size() != 1)
		throw ASNexception();
	++index;
	return sub.contents()[0] == 0xFF;
}

CertificateExtension getExtension(const AsnObject& obj, size_t& index) {
	if (obj.numSubObjects() - 1 < index)
		throw ASNexception();
	const AsnObject& sub = obj.subObjects(index);
	if (!checkClassAndTag(sub, tagClass::universal, tagNum::sequence))
		throw ASNexception();
	if (sub.numSubObjects() != 2 && sub.numSubObjects() != 3)
		throw ASNexception();
	size_t i = 0;
	ObjectID OID = getOID(sub, i);
	bool critical = false;
	tryBool(sub, i, critical);
	AsnObject ext = getObject(sub, i);
	++index;
	return {OID, critical, ext};
}

//TODO: extensions
TbsCertificate parseTbsCert(const AsnObject& obj) {
	TbsCertificate ret;
	if (obj.subObjects().size() < 6)
		throw ASNexception();	//thow exception if fields are missing
	ret.version = 0;
	size_t index = 0;
	tryVersion(obj, index, ret.version);
	getSerial(obj, index, ret.certSerial);
	//TODO: parse signature algorithm properly
	//getSigAlg(obj,index,ret.sigAlgId);
	ret.sigAlgId = nullptr;
	++index;
	getName(obj, index, ret.issuer);
	getValidity(obj, index, ret.valid);
	getName(obj, index, ret.subject);
	//getPubKey(obj, index, ret.subjectPubKey)
	ret.subjectPubKey = nullptr;
	++index;
	tryIssuerID(obj, index, ret.issuerID);
	trySubjectID(obj, index, ret.subjectID);
	//extensions
	if (index != obj.numSubObjects()) {
		const AsnObject& sub = obj.subObjects(index);
		if (!checkClassAndTag(sub, tagClass::contextSpecific, 3)) //context-specific 3 is an extension list
			throw ASNexception();
		if (sub.numSubObjects() == 0)
			throw ASNexception();
		const AsnObject& extensions = sub.subObjects(0);
		if (!checkClassAndTag(obj, tagClass::universal, tagNum::sequence)) //extension list is an explicitly tagged sequence
			throw ASNexception();
		size_t i = 0;
		while (i < extensions.numSubObjects())
			ret.extensions.push_back(getExtension(extensions, i));
	}
	return ret;
}

std::string displayTime(AsnTime at) {
	std::stringstream ss;
	ss << at.day << "/" << at.month << "/" << at.year << " ";
	if (at.hour < 10)
		ss << "0";
	ss << at.hour << ":";
	if (at.min < 10)
		ss << "0";
	ss << at.min;
	if (at.hasSeconds) {
		ss << ":";
		if (at.min < 10)
			ss << "0";
		ss << at.sec;
	}
	if (at.tzMin != 0) {
		int tzHr = abs(at.tzMin) / 60;
		int tzMin = abs(at.tzMin) % 60;
		ss << " (";
		if (at.tzMin < 0) {
			ss << "-";
		}
		else {
			ss << "+";
		}
		if (tzHr < 10)
			ss << "0";
		ss << tzHr << ":";
		if (tzMin < 10)
			ss << "0";
		ss << tzMin << ")";
	}
	return ss.str();
}

vector<char> asnObjectToVect(AsnObject obj) {
	return vector<char>(0);
}

ObjectID::ObjectID(const vector<char>& v) : _segs(parseOID(v)) {}
ObjectID::ObjectID(std::istream& is, size_t cnt) : _segs(parseOID(is, cnt)) {}
std::string ObjectID::displayForm() {
	std::stringstream ss;
	for (size_t i = 0; i < _segs.size() - 1; ++i) {
		ss << _segs[i] << ".";
	}
	ss << _segs.back();
	return ss.str();
}

vector<char> ObjectID::encodedForm() {
	std::stringstream ss;
	if (_segs.size() < 2) {
		cerr << "ObjectID::encodedForm: too few segments in OID" << endl;
		throw EncodingException();
	}
	ss << ((char)(unsigned char)(_segs[0] * 40 + _segs[1]));
	for (size_t i = 2; i < _segs.size(); ++i) {
		appendSeptets(ss, _segs[i]);
	}
	vector<char> ret = stringToVec(ss.str());
	return ret;
}

bool ObjectID::operator== (ObjectID rhs) {
	return _segs == rhs._segs;
}

//lexicographical order
bool ObjectID::operator <(ObjectID rhs) {
	vector<size_t>::iterator checkIt, endIt;
	auto it1 = _segs.begin();
	auto it2 = rhs._segs.begin();
	if (_segs.size() <= rhs._segs.size()) {
		checkIt = _segs.begin();
		endIt = _segs.end();
	}
	else {
		checkIt = rhs._segs.begin();
		endIt = rhs._segs.end();
	}
	for (; checkIt != endIt; ++checkIt, ++it1, ++it2) {
		if (*it1 < *it2)
			return true;
		if (*it1 > *it2)
			return false;
	}
	if (_segs.size() < rhs._segs.size())
		return true;
	else
		return false;
}

codedString::codedString(vector<char> bytesIn, std::string tag) : _contents(stringFromVec(bytesIn)), _tag(tag) {
}

const std::wstring codedString::getWString() {
	std::wstring ret;
	if (_tag == "ASCII") {
		for (int i = 0; i < _contents.size(); ++i) {
			ret.push_back((unsigned char)_contents[i]); //no sign extension
		}
	}
	else if (_tag == "BMP") {
		size_t len = _contents.size() / 2;
		for (int i = 0; i < len; ++i) {
			//big-endian encoding (as in ASN.1)
			ret.push_back(
				((wchar_t)(unsigned char)_contents[i * 2] << 8)
				+ (unsigned char)_contents[i * 2 + 1]
			);
		}
	}
	else if (_tag == "UTF8") {
		//get required buffer-size
		int wsize = MultiByteToWideChar(
			CP_UTF8,
			NULL,
			&_contents[0],
			(int)_contents.size(),
			nullptr,
			0
		);
		//convert UTF-8 to wide_char
		ret.resize(wsize);
		MultiByteToWideChar(
			CP_UTF8,
			NULL,
			&_contents[0],
			(int)_contents.size(),
			&ret[0],
			wsize
		);
	}
	else {
		cerr << "codedString::getWString: invalid encoding" << endl;
		throw EncodingException();
	}
	return ret;
}

const std::string codedString::getString() {
	std::string ret;
	if (_tag == "ASCII" || _tag == "UTF8") {
		ret = _contents;
	}
	else if (_tag == "BMP") {
		std::wstring tmp = getWString();
		//get required buffer-size
		int len = WideCharToMultiByte(
			CP_UTF8,
			MB_PRECOMPOSED,
			&tmp[0],
			(int)tmp.size(),
			nullptr,
			0,
			NULL,
			NULL
		);
		//convert wchar to UTF-8
		ret.resize(len);
		WideCharToMultiByte(
			CP_UTF8,
			MB_PRECOMPOSED,
			&tmp[0],
			(int)tmp.size(),
			&ret[0],
			len,
			NULL,
			NULL
		);
	}
	else {
		cerr << "codedString::getString: invalid encoding" << endl;
		throw EncodingException();
	}
	return ret;
}

AsnObject::AsnObject(char cls, size_t tag, size_t preLength, vector<char> v) : _cls(cls), _tag(tag), _preLength(preLength), _constructed(false), _contents(v) {
};

AsnObject::AsnObject(char cls, size_t tag, size_t preLength, vector<AsnObject> v) : _cls(cls), _tag(tag), _preLength(preLength), _constructed(true), _subObj(v) {
};

size_t AsnObject::length() const {
	size_t len = 0;
	for (AsnObject a : _subObj) {
		len += a.rawLength();
	}
	len += _contents.size();
	return len;
}

size_t AsnObject::rawLength() const {
	return length() + _preLength;
}

const vector<char>& AsnObject::contents() const {
	return _contents;
}

const vector<AsnObject>& AsnObject::subObjects() const {
	return _subObj;
}

const AsnObject& AsnObject::subObjects(size_t n) const {
	return _subObj.at(n);
}

size_t AsnObject::numSubObjects() const {
	return _subObj.size();
}

char AsnObject::getClass() const {
	return _cls;
}

size_t AsnObject::getTag() const {
	return _tag;
}

bool AsnObject::isConstructed() const {
	return _constructed;
}

void AsnObject::rawOut(std::ostream& os) const {
	char lowTag = _cls << 6;
	if (_constructed)
		lowTag |= 0x20;
	if (_tag >= 0x1F) {
		os << (char)(lowTag | 0x1F);
		appendSeptets(os, _tag);
	}
	else {
		lowTag |= _tag;
		os << lowTag;
	}
	size_t len = length();
	if (len < 128) {
		os << (char)len;
	}
	else {
		char lenOfLen = 0;
		size_t tmp = len;
		while (tmp > 0) {
			++lenOfLen;
			tmp >>= CHAR_BIT;
		}
		os << (char)(lenOfLen | 0x80); //set top bit to signal long length mode
		len <<= (sizeof(size_t) - lenOfLen)*CHAR_BIT; //put the first nonzero octet at the top
		for (int i = 0; i < lenOfLen; ++i) {
			char next = len >> (CHAR_BIT*(sizeof(size_t) - 1));
			os << next;
			len <<= CHAR_BIT;
		}
	}
	if (_constructed) {
		for (AsnObject obj : _subObj) {
			obj.rawOut(os);
		}
	}
	else {
		if (_contents.size() > 0)
			os.write(&_contents[0], _contents.size());
	}
}
