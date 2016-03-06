#pragma once


#include <iostream>
#include <stdexcept>


/**
	Function encrypting stream and creating checksum at the same time. 
	Encryption uses AES-128, hash SHA-512
	@author xhunterx
	@version 1
	@param ifile	input stream to encrypt
	@param output	stream to output encrypted data
	@return			0 if successfull
	@throw			CryptoException
*/
int encryptAndHash(std::istream & ifile, std::iostream & ofile, const char * key);


/**
	Function decrypting and verifying stream at the same time.
	Encryption uses AES-128, hash SHA-512
	@author xhunterx
	@version 1
	@param ifile	input stream to decrypt
	@param output	stream to output decrypted data
	@return			0 if successfull
	@throw			CryptoException
*/
int decryptAndVerify(std::istream & ifile, std::ostream & ofile, const char * key);








class CryptoException : public std::runtime_error {
public:
	CryptoException(const char * message) : runtime_error(message) {};
};

class CryptoVerifycationException : public CryptoException {
public:
	CryptoVerifycationException(const char * message) : CryptoException(message) {};
};