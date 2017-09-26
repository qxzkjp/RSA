#pragma once
#include "../RSA/interfaces.h"

class ASNexception : public std::exception {
public:
	virtual std::string what() {
		return "generic ASN exception";
	}
};

class EOFexception : public ASNexception {
public:
	virtual std::string what() {
		return "unexpected EOF";
	}
};

class EncodingException : public ASNexception {
public:
	virtual std::string what() {
		return "Malformed or unsupported encoding";
	}
};

class SizeException : public ASNexception {
public:
	virtual std::string what() {
		return "Parameter too large";
	}
};

class ObjectID {
public:
	ObjectID(const std::vector<char>& v);
	ObjectID(std::istream& is, size_t cnt);
	std::string displayForm();
	std::vector<char> encodedForm();
	bool operator== (ObjectID rhs);
	bool operator <(ObjectID rhs);
private:
	std::vector<size_t> _segs;
};

struct PublicKey {

};

class codedString {
public:
	codedString(std::vector<char> bytesIn = std::vector<char>(), std::string tag = "UTF8");
	const std::wstring getWString();
	const std::string getString();
private:
	std::string _contents;
	std::string _tag;
};

class AsnObject {
public:
	AsnObject(char cls, size_t tag, size_t preLength, std::vector<char> v);
	AsnObject(char cls, size_t tag, size_t preLength, std::vector<AsnObject> v);
	size_t AsnObject::length() const;
	size_t AsnObject::rawLength() const;
	const std::vector<char>& contents() const;
	const std::vector<AsnObject>& subObjects() const;
	const AsnObject& subObjects(size_t n) const;
	size_t numSubObjects() const;
	char getClass() const;
	size_t getTag() const;
	bool isConstructed() const;
	void rawOut(std::ostream& os) const;
private:
	char _cls;
	size_t _tag;
	size_t _preLength;
	bool _constructed;
	std::vector<char> _contents;
	std::vector<AsnObject> _subObj;
};

struct AsnTime {
	int sec;
	int min;
	int hour;
	int day;
	int month;
	int year;
	int tzMin;
	bool hasSeconds;
};

typedef std::shared_ptr<AsnObject> AsnPtr;
typedef std::shared_ptr<const AsnObject> AsnConstPtr;

typedef std::pair<ObjectID, codedString> nameElement;
typedef std::vector<nameElement> subName;
typedef std::vector<subName> nameType;

struct Validity {
	AsnTime begin;
	AsnTime end;
};

struct CertificateExtension {
	ObjectID id;
	bool critical;
	AsnObject contents;
};

struct TbsCertificate {
	char version;
	std::vector<char> certSerial;
	verifyPtr sigAlgId;
	nameType issuer;
	Validity valid;
	nameType subject;
	verifyPtr subjectPubKey;
	std::vector<char> issuerID;
	std::vector<char> subjectID;
	std::vector<CertificateExtension> extensions;
};

AsnObject parseObject(std::istream& is);
void printAsnObject(AsnObject obj, size_t depth = 0);
TbsCertificate parseTbsCert(const AsnObject& obj);
