
#include "crypto.h"
#include <sstream>
#include <fstream>

#include "mbedtls/base64.h"

#define CATCH_CONFIG_MAIN
#include "catch.hpp"

using namespace std;

TEST_CASE("Bad input file", "[Crypto]") {
	ifstream ifile;
	stringstream ofile;

	const char * key = "MySecretKey01234";

	CHECK_THROWS_AS(encryptAndHash(ifile, ofile, key), CryptoException);
	CHECK_THROWS_AS(decryptAndVerify(ifile, ofile, key), CryptoException);
}

TEST_CASE("Bad output file", "[Crypto]") {
	stringstream ifile;
	ofstream ofile;

	const char * key = "MySecretKey01234";

	CHECK_THROWS_AS(encryptAndHash(ifile, ofile, key), CryptoException);
	CHECK_THROWS_AS(decryptAndVerify(ifile, ofile, key), CryptoException);
}

TEST_CASE("Bad key length", "[Crypto]") {
	stringstream ifile;
	stringstream ofile;

	const char * key = "MySecretKey";

	CHECK_THROWS_AS(encryptAndHash(ifile, ofile, key), CryptoException);
	CHECK_THROWS_AS(decryptAndVerify(ifile, ofile, key), CryptoException);
}

// Not possible to check with random IV, is tested in combined instead

/*TEST_CASE("Encryption Testing", "[Crypto]") {
	stringstream ifile;
	stringstream ofile;
	
	const char * testdata	= "Hello world!";
	std::string expected64 = "Gm0w/KqaDYSmp0UGN9u6O26TlS0bH1MD0+37Ks5qH9Ww2CvrweFA2EO6NsapNSqclVv4bSI9+m6+TGmjLugpf0zib3WHRRuFs4RwMU926r0ifu7go5nP3sErOpAMGFZm";
	const char * key = "MySecretKey01234";

	char result64[256];
	size_t len;
	ifile << testdata;

	CHECK(encryptAndHash(ifile, ofile, key) == 0);

	mbedtls_base64_encode(reinterpret_cast<unsigned char *>(result64), 256, &len, reinterpret_cast<const unsigned char *>(ofile.str().c_str()), ofile.str().length());

	CHECK(ofile.str() != testdata);
	CHECK(ofile.str().length() == 96);
	CHECK(expected64 == result64);

}*/

TEST_CASE("Decryption Testing", "[Crypto]") {
	stringstream ifile;
	stringstream ofile;

	const char * testdata64	= "B076QG8yhd1q/YR/XtZdN17KGXdvYD5eErVIXXDg1cAVy+GqhHFCjDw2xToFkIwq2JlFU1oceMPRuaXv2iHBdRk2FB0Ck+mogt4S96eqeFpe2SyWtPFaEoSVcpx4rdim";
	const char * expected	= "Hello world!";
	const char * key = "MySecretKey01234";

	char testdata[256];
	size_t len;
	mbedtls_base64_decode(reinterpret_cast<unsigned char *>(testdata), 256, &len, reinterpret_cast<const unsigned char *>(testdata64), strlen(testdata64));
	ifile.write(testdata, len);

	CHECK(decryptAndVerify(ifile, ofile, key) == 0);
	CHECK(ofile.str() == expected);
}

TEST_CASE("Decryption Testing Bad Key", "[Crypto]") {
	stringstream ifile;
	stringstream ofile;

	const char * testdata64 = "B076QG8yhd1q/YR/XtZdN17KGXdvYD5eErVIXXDg1cAVy+GqhHFCjDw2xToFkIwq2JlFU1oceMPRuaXv2iHBdRk2FB0Ck+mogt4S96eqeFpe2SyWtPFaEoSVcpx4rdim";
	const char * expected = "Hello world!";
	const char * key = "MySecretKey00234";

	char testdata[256];
	size_t len;
	mbedtls_base64_decode(reinterpret_cast<unsigned char *>(testdata), 256, &len, reinterpret_cast<const unsigned char *>(testdata64), strlen(testdata64));
	ifile.write(testdata, len);

	CHECK_THROWS(decryptAndVerify(ifile, ofile, key));
}

TEST_CASE("Decryption Testing Bad Hash", "[Crypto]") {
	stringstream ifile;
	stringstream ofile;

	const char * testdata64 = "B076QG8yhd1q/YR/XtZdF17KGXdvYD5eErVIXXDg1cAVy+GqhHFCjDw2xToFkIwq2JlFU1oceMPRuaXv2iHBdRk2FB0Ck+mogt4S96eqeFpe2SyWtPFaEoSVcpx4rdim";
	const char * expected = "Hello world!";
	const char * key = "MySecretKey01234";

	char testdata[256];
	size_t len;
	mbedtls_base64_decode(reinterpret_cast<unsigned char *>(testdata), 256, &len, reinterpret_cast<const unsigned char *>(testdata64), strlen(testdata64));
	ifile.write(testdata, len);

	CHECK_THROWS_AS(decryptAndVerify(ifile, ofile, key), CryptoVerifycationException);
}

TEST_CASE("Decryption Testing Bad Data", "[Crypto]") {
	stringstream ifile;
	stringstream ofile;

	const char * testdata64 = "B076QG8yhd1q/YR/XtZdN17KGXdvYD5eErVIXXDg1cAVy+GqhHFCjDw2xToFkIwq2JlFU1oceMPRuaXv2iHBdRk2FB0Ck+mogt4S96eqeFpe2SyWtPFaFoSVcpx4rdim";
	const char * expected = "Hello world!";
	const char * key = "MySecretKey01234";

	char testdata[256];
	size_t len;
	mbedtls_base64_decode(reinterpret_cast<unsigned char *>(testdata), 256, &len, reinterpret_cast<const unsigned char *>(testdata64), strlen(testdata64));
	ifile.write(testdata, len);

	CHECK_THROWS_AS(decryptAndVerify(ifile, ofile, key), CryptoVerifycationException);
}

TEST_CASE("Test Random IV", "[Crypto]") {
	stringstream ifile;
	stringstream ofile1;
	stringstream ofile2;

	const char * testdata = "Hello world!";
	const char * key = "MySecretKey01234";

	ifile.write(testdata, strlen(testdata));
	CHECK(encryptAndHash(ifile, ofile1, key) == 0);

	ifile.clear();
	ifile.write(testdata, strlen(testdata));
	CHECK(encryptAndHash(ifile, ofile2, key) == 0);

	CHECK(ofile1.str().length() > 64);
	CHECK(ofile2.str().length() > 64);
	CHECK(ofile1.str() != ofile2.str());
}

TEST_CASE("Combined Testing", "[Crypto]") {
	stringstream ifile;
	stringstream ofile;
	stringstream nfile;

	const char * testdata = "Aloha from da hell! How are you? I am fine! Your name is Fine? No, my name is Ted! Hello Ted!My name is Fred. Hello Fred. What else? Nothing else! Type type type the boat, bla bla bla bla bla. Blabiti blabity blabiti bla. AES Encryption! Tun tun tun!";
	const char * key = "MySecretKey01234";
	
	ifile << testdata;

	CHECK(ifile.str() == testdata);
	CHECK(encryptAndHash(ifile, ofile, key) == 0);
	CHECK(decryptAndVerify(ofile, nfile, key) == 0);
	CHECK(nfile.str() == testdata);
}
