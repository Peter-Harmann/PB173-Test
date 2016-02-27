

#include <cstring>
#include <string>
#include <iostream>
#include <fstream>

#include "mbedtls/aes.h"
#include "mbedtls/sha512.h"
#include "mbedtls/base64.h"

using namespace std;

#define BUFFER_SIZE 128




size_t add_padding(char * str, size_t len) {
	char add = 16 - (len % 16);
	for (size_t i = len; i < len + add; ++i) {
		str[i] = add;
	}
	return len + add;
}

size_t remove_padding(unsigned char * str, size_t len) {
	unsigned char rem = str[len-1];
	cout << len - rem;
	return len - rem;
}



int main(int argc, char ** argv) {
	if (argc != 5) return 1;

	if (std::string("-e").compare(argv[1]) == 0) {
		ifstream ifile;
		fstream ofile;
		ifile.open(argv[3], fstream::in | fstream::binary);
		ofile.open(argv[4], fstream::out | fstream::binary);

		if (ifile) {
			mbedtls_sha512_context sha;
			mbedtls_sha512_init(&sha);
			mbedtls_sha512_starts(&sha, 0);

			mbedtls_aes_context aes;
			mbedtls_aes_init(&aes);
			mbedtls_aes_setkey_enc(&aes, reinterpret_cast<unsigned char *>(argv[2]), 128);

			char buffer[BUFFER_SIZE + 16];
			unsigned char obuffer[BUFFER_SIZE + 16];
			unsigned char iv[17] = "0123456789012345";
			size_t len = BUFFER_SIZE;
			unsigned char hash[64];
			ofile.write(reinterpret_cast<char *>(hash), 64);
			ofile.write(reinterpret_cast<char *>(iv), 16);

			while (!ifile.eof()) {
				ifile.read(buffer, BUFFER_SIZE);
				if (ifile.eof()) {
					len = add_padding(buffer, ifile.gcount());
				}
				mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, len, iv, reinterpret_cast<unsigned char *>(buffer), obuffer);
				mbedtls_sha512_update(&sha, obuffer, len);

				ofile.write(reinterpret_cast<char *>(obuffer), len);
			}

			
			mbedtls_sha512_finish(&sha, hash);
			ofile.seekg(0, ofile.beg);
			ofile.write(reinterpret_cast<char *>(hash), 64);

			ifile.close();
			ofile.close();
		}
	}
	else if (std::string("-d").compare(argv[1]) == 0) {
		ifstream ifile;
		ofstream ofile;
		ifile.open(argv[3], fstream::in | fstream::binary);
		ofile.open(argv[4], fstream::out | fstream::binary);

		//ifile.seekg(0, ifile.end);
		//size_t iFileLength = ifile.tellg();
		//ifile.seekg(0, ifile.beg);

		if (ifile) {
			mbedtls_sha512_context sha;
			mbedtls_sha512_init(&sha);
			mbedtls_sha512_starts(&sha, 0);

			mbedtls_aes_context aes;
			mbedtls_aes_init(&aes);
			mbedtls_aes_setkey_dec(&aes, reinterpret_cast<unsigned char *>(argv[2]), 128);

			char buffer[BUFFER_SIZE + 16];
			unsigned char obuffer[BUFFER_SIZE + 16];
			unsigned char iv[16];
			size_t len = BUFFER_SIZE;
			unsigned char ohash[64];

			ifile.read(reinterpret_cast<char *>(ohash), 64);
			ifile.read(reinterpret_cast<char *>(iv), 16);

			while (!ifile.eof()) {
				ifile.read(buffer, BUFFER_SIZE);

				if (ifile.eof()) len = ifile.gcount();

				mbedtls_sha512_update(&sha, reinterpret_cast<unsigned char *>(buffer), len);
				mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, len, iv, reinterpret_cast<unsigned char *>(buffer), obuffer);

				if (ifile.eof()) {
					len = remove_padding(obuffer, len);
				}

				ofile.write(reinterpret_cast<char *>(obuffer), len);
			}

			unsigned char hash[64];
			mbedtls_sha512_finish(&sha, hash);

			if (memcmp(ohash, hash, 64) != 0) return 2;

			//unsigned char ehash[129];
			//size_t olen;
			//mbedtls_base64_encode(ehash, 129, &olen, hash, 64);

			//ofile.write(reinterpret_cast<char *>(hash), 64);

			ifile.close();
			ofile.close();
		}
	}
	
	//cin.get();
	return 0;
}




