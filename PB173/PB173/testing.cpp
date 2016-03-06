
#include "crypto.h"
#include <sstream>
#include <fstream>

#define CATCH_CONFIG_MAIN
#include "catch.hpp"

using namespace std;


TEST_CASE("Encryption Testing", "[Crypto]") {
	stringstream ifile;
	stringstream ofile;
	
	const char * testdata = "Hello world!";
	const char * key = "MySecretKey01234";
	ifile << testdata << endl;

	CHECK(encryptAndHash(ifile, ofile, key) == 0);
	CHECK(ofile.str() != testdata);
	CHECK(ofile.str().length() > 64);
}

TEST_CASE("Decryption Testing", "[Crypto]") {
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