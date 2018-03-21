// RSA.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <memory>
#include <fstream>
#include <sstream>
#include "randomNumbers.h"
#include "mpzConvert.h"
#include "RsaDecryptor.h"
#include "../SHA1/Sha1Class.h"
#include "mgf1.h"


void printVec(charBuf buf, std::ostream& os = std::cout, bool wrap=true) {
	std::ios::fmtflags flg(os.flags());
	os << std::hex;
	for (int i = 0; i < buf.size(); ++i) {
		if ((buf[i] & 0xF0) == 0)
			os << "0";
		os << (int)(unsigned char)buf[i];
		if (wrap && i % 4 == 3 && i % 32 != 31)
			os << " ";
		if (wrap && (i % 32 == 31))
			os << std::endl;
	}
	os.flags(flg);
}

std::string formatVec(charBuf buf) {
	std::stringstream ss;
	printVec(buf, ss, false);
	return ss.str();
}

//this function is generally stupid and is only for use in MGF1 testing
inline char sizeToChar(size_t n) {
	char m;
	if (n <= CHAR_MAX)
		m = (char)n;
	else
		m = (char)CHAR_MIN + ((char)n - CHAR_MAX - 1);
	return m;
}

void mgf1Test() {
	int testLen = 0x10000;
	charBuf v = MGF1<Sha1Class>({ 1,2,3,4,5,6,7,8,9,10 }, testLen);
	Sha1Class sha;
	charBuf tmp(20);
	charBuf w(0);
	size_t n = 255;
	for (size_t j = 0; j <= UCHAR_MAX; ++j) {
		char sj = sizeToChar(j);
		for (size_t i = 0; i <= UCHAR_MAX; ++i) {
			char si = sizeToChar(i);
			sha.addData({ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, sj, si });
			sha.finalise(tmp.begin());
			w.insert(w.end(), tmp.begin(), tmp.end());
			sha.reset();
		}
	}
	bool calcTest = memcmp(&v[0], &w[0], testLen) == 0;
	std::cout << "MGF1 calculation test ";
	if (calcTest)
		std::cout << "successful";
	else
		std::cout << "failed";
	std::cout << std::endl;
	bool truncTest = true;
	for (int i = 1; i < testLen/0x100; ++i) {
		w = MGF1<Sha1Class>({ 1,2,3,4,5,6,7,8,9,10 }, i);
		truncTest = truncTest && (memcmp(&v[0], &w[0], i) == 0);
	}
	for (int i = testLen / 0x100; i < testLen; i+=0x50) {
		w = MGF1<Sha1Class>({ 1,2,3,4,5,6,7,8,9,10 }, i);
		truncTest = truncTest && (memcmp(&v[0], &w[0], i) == 0);
	}
	std::cout << "MGF1 truncation test ";
	if (truncTest)
		std::cout << "successful";
	else
		std::cout << "failed";
	std::cout << std::endl;
}

charBuf stringToBuffer(const std::string& str) {
	charBuf ret(str.length());
	std::copy(str.begin(), str.end(), ret.begin());
	return ret;
}

int testRsaOaep(std::string filename="rsaLog.txt") {
	std::fstream fs(filename, std::ios::out | std::ios::app);
	if (!fs)
		std::cerr << "Could not open log file" << std::endl;
	std::ostringstream ss;
	auto pk = newRsaPrivateKey(2048);
	ss << "N:\t\t" << pk.N << std::endl;
	ss << "e:\t\t" << pk.e << std::endl;
	ss << "d:\t\t" << pk.d << std::endl;
	ss << "p:\t\t" << pk.p << std::endl;
	ss << "q:\t\t" << pk.q << std::endl;
	ss << "dp:\t\t" << pk.dp << std::endl;
	ss << "dq:\t\t" << pk.dq << std::endl;
	ss << "qinv:\t" << pk.qinv << std::endl << std::endl;
	std::cout << ss.str();
	fs << ss.str();
	ss.str("");
	ss.clear();
	RsaOaepDecryptor<MGF1_class<Sha1Class>, Sha1Class> key(pk);
	bool success = true;
	for (size_t l = 0x10; l <= 0xd0; l += 0x10) {
		std::cout << "Message size: " << l << std::endl;
		for (int i = 0; i < 200; ++i) {
			charBuf M = getRandomBuffer(l);
			charBuf C;
			charBuf Mprime;
			C = key.encrypt(M);
			Mprime = key.decrypt(C);
			bool roundSuccess = (M == Mprime);
			success = success && roundSuccess;
			if (roundSuccess) {
				std::cout << std::hex << "M:\t" << vectorToMpzClass(M) << std::endl << "M':\t" << vectorToMpzClass(Mprime) << std::endl;
				std::cout << "Success!" << std::endl;
			}
			else {
				ss << std::hex << "M:\t\t" << vectorToMpzClass(M) << std::endl;
#ifdef _DEBUG
				ss << "Seed:\t" << formatVec(key.getLastSeed()) << std::endl;
#endif
				ss << std::hex << "C:\t\t" << vectorToMpzClass(C) << std::endl;
				ss << "M':\t\t" << vectorToMpzClass(Mprime) << std::endl;
				std::cout << ss.str();
				fs << ss.str() << std::endl;
				ss.str("");
				ss.clear();
				std::cout << "Failure!" << std::endl;
			}
		}
		std::cout << std::endl;
	}
	fs << "-----" << std::endl << std::endl;
	if (success) {
		std::cout << "All succeded!" << std::endl;
		return 0;
	}
	else {
		std::cout << "Some failures." << std::endl;
		return 1;
	}
}

std::vector<char> hexStrToVec(std::string s) {
	std::stringstream ss;
	char c;
	std::vector<char> ret;
	for (size_t i = 0; i < s.size(); i += 2) {
		c = (char)stoi(s.substr(i, 2), nullptr, 16);
		ret.push_back(c);
	}
	return ret;
}

bool testSpecificCase(
	std::string nStr,
	std::string eStr,
	std::string dStr,
	std::string pStr,
	std::string qStr,
	std::string dpStr,
	std::string dqStr,
	std::string qInvStr,
	std::string seed,
	std::string msg
) {
	rsaPrivateKey pk = {
		mpz_class(nStr),
		mpz_class(eStr),
		mpz_class(dStr),
		mpz_class(pStr),
		mpz_class(qStr),
		mpz_class(dpStr),
		mpz_class(dqStr),
		mpz_class(qInvStr) };
	RsaOaepDecryptor<MGF1_class<Sha1Class>, Sha1Class> dec(pk);
	charBuf M = hexStrToVec(msg);
	dec.setNextSeed(hexStrToVec(seed));
	charBuf C = dec.encrypt(M);
	charBuf mPrime = dec.decrypt(C);
	return (M == mPrime);
}

int main()
{
	testRsaOaep();
	/*bool test = testSpecificCase(
		"23529116570276170500575897077686750434541133904607899218416483882190156018223889317041470533098054863367288597759123305438458975669671706444719168912308323273044309764143958670335604151495112319910264781399818240351770155408995019264304581779141283223752628119668745155405139452627702537684888151099367461820773661107523140270147662497813964303340354845230715891888345368563491283556341913547712701310013337324360900202133732354695978518785242229170807632037445415522319091409851049214728620528449252419995645294998763968410509067711123670541410636773221718232858665331857830978873540472550176042861809179059465106917",
		"65537",
		"8552403228387533692104745902865784602231130831570213333407209222265175421336350143673091388134875168648303482483466680203583479392024116988462665093680710481847277492814063986227620951444845173394302035340582727505679124114246530225744718172205228776334333746626928494125204532871062392258732671489594915723274585699512798314234671798128295180104883952767885084716888177450169398545965369437903979441308548400869177227043632475386943269612715963195152241598487689833727277781993391802663950715584560894879012993069908689792383139144541916538648600085741369074689130753296629248560935624114418122996358121859110661283",
		"147719870279650296595445953590549431158288837782145342926933209193351335774295708671504374270089564283678843257756812963695434880685411757858261542734573893659143977462964714397574765307007889859551254471691109110432271285608129903543103008939540037567431440049568121480325947159475234639669201149693438307407",
		"159282001302417282076126221030749371750364409625222531536367536422309128039085752475985289000965758786845679389279274761592903436575637365088307797942542082968353855671861633661845107323648806786555850029200541292378950844247869463986599158433382282850516259886374204972680706761111940730404902711385188673931",
		"27176380914014123717156596463696148610334444926367187995636567179520531233206942024388181341447882517788666145212229639795472150944108054450113057063197238748314676232829784114188305007958773334705730734778517517501287744183853735249083616564445034605650561860897551622568777101512014648984414273797302068639",
		"11230940201999942940228867164854858276369591785985829656980856398789851239278808340197568098531558834765306383536926143603167779733830054230023808448547949484974337657501451228334928985803151443622298594457111270154006619943992016617820081955546630591150581151638543131036781450830802113541984763252986204163",
		"96823264181447168260819609898340217270246495872566602044327360656523649465651912976367028193731757254186541807781625467085937537845172050504407552559316112155439811556505506837301743861933160019825181847210044754986128558138286815307246988946820026739315847147130915240035313267716698909542229847778558446650",
		"e8d2593ccfbd6f3d6973d99393330c4e792a3cbe",
		"cedb823896f9909f16ed6fd4022b1b0e546205f2f840eb52ad748be1f540804676f5f013074d817e8a99ab4691452f11"
	);*/
	return 0;
}

