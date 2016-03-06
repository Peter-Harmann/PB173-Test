


#include <cstring>
#include <string>
#include <iostream>
#include <fstream>

#include "mbedtls/aes.h"
#include "mbedtls/sha512.h"
#include "mbedtls/base64.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

#include "crypto.h"

#define BUFFER_SIZE 128

using namespace std;


size_t add_padding(char * str, size_t len) {
	char add = 16 - (len % 16);
	for (size_t i = len; i < len + add; ++i) {
		str[i] = add;
	}
	return len + add;
}

size_t remove_padding(unsigned char * str, size_t len) {
	unsigned char rem = str[len - 1];
	return len - rem;
}

int encryptAndHash(istream & ifile, iostream & ofile, const char * key) {
	if (ifile && ofile) {
		mbedtls_entropy_context entropy;
		mbedtls_entropy_init(&entropy);
		mbedtls_entropy_gather(&entropy);

		mbedtls_ctr_drbg_context ctr_drbg;
		const char *personalization = "]76kXV-$P?0qdQtfpkTPUSvWcq&(dyub";

		mbedtls_ctr_drbg_init(&ctr_drbg);
		mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)personalization, strlen(personalization));

		mbedtls_sha512_context sha;
		mbedtls_sha512_init(&sha);
		mbedtls_sha512_starts(&sha, 0);

		mbedtls_aes_context aes;
		mbedtls_aes_init(&aes);
		mbedtls_aes_setkey_enc(&aes, reinterpret_cast<const unsigned char *>(key), 128);

		char buffer[BUFFER_SIZE + 16];
		unsigned char obuffer[BUFFER_SIZE + 16];
		unsigned char iv[16];
		size_t len = BUFFER_SIZE;
		unsigned char hash[64];

		mbedtls_ctr_drbg_random(&ctr_drbg, iv, 16);
		ofile.write(reinterpret_cast<char *>(hash), 64);
		ofile.write(reinterpret_cast<char *>(iv), 16);

		while (!ifile.eof()) {
			ifile.read(buffer, BUFFER_SIZE);
			if (ifile.eof()) {
				len = add_padding(buffer, static_cast<size_t>(ifile.gcount()));
			}
			mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, len, iv, reinterpret_cast<unsigned char *>(buffer), obuffer);
			mbedtls_sha512_update(&sha, obuffer, len);

			ofile.write(reinterpret_cast<char *>(obuffer), len);
		}


		mbedtls_sha512_finish(&sha, hash);
		ofile.seekg(0, ofile.beg);
		ofile.write(reinterpret_cast<char *>(hash), 64);
	}
	else {
		if (!ifile) {
			cout << "Invalid input file!" << endl;
			return 3;
		}
		if (!ofile) {
			cout << "Invalid output file!" << endl;
			return 4;
		}
	}
	return 0;
}


int decryptAndVerify(istream & ifile, ostream & ofile, const char * key) {
	if (ifile && ofile) {
		mbedtls_sha512_context sha;
		mbedtls_sha512_init(&sha);
		mbedtls_sha512_starts(&sha, 0);

		mbedtls_aes_context aes;
		mbedtls_aes_init(&aes);
		mbedtls_aes_setkey_dec(&aes, reinterpret_cast<const unsigned char *>(key), 128);

		char buffer[BUFFER_SIZE + 16];
		unsigned char obuffer[BUFFER_SIZE + 16];
		unsigned char iv[16];
		size_t len = BUFFER_SIZE;
		unsigned char ohash[64];

		ifile.read(reinterpret_cast<char *>(ohash), 64);
		ifile.read(reinterpret_cast<char *>(iv), 16);

		while (!ifile.eof()) {
			ifile.read(buffer, BUFFER_SIZE);

			if (ifile.eof()) len = static_cast<size_t>(ifile.gcount());

			mbedtls_sha512_update(&sha, reinterpret_cast<unsigned char *>(buffer), len);
			mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, len, iv, reinterpret_cast<unsigned char *>(buffer), obuffer);

			if (ifile.eof()) {
				len = remove_padding(obuffer, len);
			}

			ofile.write(reinterpret_cast<char *>(obuffer), len);
		}

		unsigned char hash[64];
		mbedtls_sha512_finish(&sha, hash);

		if (memcmp(ohash, hash, 64) != 0) {
			//ofile.open(argv[4], fstream::out | fstream::binary);
			//ofile.close();
			cout << "File is corrupted or invalid format!" << endl;
			cout << "Press any key to continue!";
			cin.get();
			return 2;
		}
	}
	else {
		if (!ifile) {
			cout << "Invalid input file!" << endl;
			return 3;
		}
		if (!ofile) {
			cout << "Invalid output file!" << endl;
			return 4;
		}
	}
	return 0;
}
