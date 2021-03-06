


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


void print_bin_data(unsigned char * data, size_t len) {
	short tmp;
	for (size_t i = 0; i < len; ++i) {
		tmp = data[i];
		cout << tmp << " ";
	}
	cout << endl << endl;
}

size_t add_padding(char * str, size_t len) {
	char add = 16 - (len % 16);
	for (size_t i = len; i < len + add; ++i) {
		str[i] = add;
	}
	return len + add;
}

size_t remove_padding(unsigned char * str, size_t len) {
	unsigned char rem = str[len - 1];
	if (rem > len) {
		//cout << "Padd:" << endl;
		//print_bin_data(str, len);
		throw CryptoException("Wrong padding!");
	}
	for (size_t i = len - 1; i >= len - rem; --i) {
		if (str[i] != rem) {
			throw CryptoException("Wrong padding!");
		}
	}
	return len - rem;
}

int encryptAndHash(istream & ifile, ostream & ofile, const char * key) {
	if (strlen(key) != 16) throw CryptoException("Key has to be 16 characters long!");

	// Validate streams
	ifile.peek();
	ofile << 'c';
	ofile.seekp(-1, ios_base::cur);
	//------------------------------

	if (ifile.good() && ofile.good()) {
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
		ofile.seekp(ofile.beg);
		ofile.write(reinterpret_cast<char *>(hash), 64);
	}
	else {
		if (!ifile.good()) throw CryptoException("Invalid input file!");
		else throw CryptoException("Invalid output file!");
	}
	return 0;
}


int decryptAndVerify(istream & ifile, ostream & ofile, const char * key) {
	if (strlen(key) != 16) throw CryptoException("Key has to be 16 characters long!");

	// Validate streams
	ifile.peek();
	ofile << 'c';
	ofile.seekp(-1, ios_base::cur);
	//------------------------------

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
		bool end = false;

		ifile.read(reinterpret_cast<char *>(ohash), 64);
		ifile.read(reinterpret_cast<char *>(iv), 16);

		while (!end) {
			ifile.read(buffer, BUFFER_SIZE);
			len = static_cast<size_t>(ifile.gcount());

			end = ifile.peek() == EOF;

			mbedtls_sha512_update(&sha, reinterpret_cast<unsigned char *>(buffer), len);
			mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, len, iv, reinterpret_cast<unsigned char *>(buffer), obuffer);

			if (end) {
				unsigned char hash[64];
				mbedtls_sha512_finish(&sha, hash);

				if (memcmp(ohash, hash, 64) != 0) throw CryptoVerifycationException("File is corrupted or invalid format!");
				len = remove_padding(obuffer, len);
			}

			ofile.write(reinterpret_cast<char *>(obuffer), len);
		}
	}
	else {
		if (!ifile.good()) throw CryptoException("Invalid input file!");
		else throw CryptoException("Invalid output file!");
	}
	return 0;
}
