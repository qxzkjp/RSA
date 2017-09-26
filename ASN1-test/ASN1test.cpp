// ASN1test.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "../ASN1/ASN1.h"

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

int main(int argc, const char * argv[])
{
	std::string fname("wikipedia.cer");
	if (argc > 1)
		fname = std::string(argv[1]);
	fstream certFile(fname, ios::binary | ios::in);
	if (!certFile) {
		cerr << "File not found." << endl;
		return 1;
	}
	AsnObject cert = parseObject(certFile);
	certFile.close();
	printAsnObject(cert);
	TbsCertificate tbs = parseTbsCert(cert.subObjects(0));
	//cout << displayTime(tbs.valid.begin) << endl;
	//cout << displayTime(tbs.valid.end) << endl;
	std::stringstream ss("\xDF\x8D\xF5\xB6\xFD\x6F\x0B\xDE\xAD\xBE\xEF\xBA\xDC\xAB\xDE\xAD\xBE\xEF");
	AsnObject largeTag = parseObject(ss);
	assert(largeTag.getClass() == 3);
	assert(largeTag.getTag() == 0xDEADBEEF);
	assert(largeTag.length() == 11);
	certFile.open("test.cer", ios::binary | ios::trunc | ios::out);
	if (!certFile) {
		cerr << "Could not open test file for writing" << endl;
		return 1;
	}
	ss.clear();
	cert.rawOut(certFile);
	certFile.close();
	cert.rawOut(ss);
	std::string str = ss.str();
	return 0;
}
