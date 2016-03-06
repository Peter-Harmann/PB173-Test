

#include <cstring>
#include <string>
#include <iostream>
#include <fstream>

#include "crypto.h"

using namespace std;


int main(int argc, const char ** argv) {
	if (argc != 5) return 1;
	if (strlen(argv[2]) != 16) {
		cout << "Key has to be 16 characters long!";
		return 6;
	}


	if (std::string("-e").compare(argv[1]) == 0) {
		ifstream ifile;
		fstream ofile;

		ifile.open(argv[3], fstream::in | fstream::binary);
		ofile.open(argv[4], fstream::out | fstream::binary);

		int ret = encryptAndHash(ifile, ofile, argv[2]);

		ifile.close();
		ofile.close();

		if (ret) return ret;

	}
	else if (std::string("-d").compare(argv[1]) == 0) {
		ifstream ifile;
		ofstream ofile;
		ifile.open(argv[3], fstream::in | fstream::binary);
		ofile.open(argv[4], fstream::out | fstream::binary);

		int ret = decryptAndVerify(ifile, ofile, argv[2]);

		ifile.close();
		ofile.close();

		if (ret) {
			if (ret == 2) {
				ofile.open(argv[4], fstream::out | fstream::binary);
				ofile.close();
			}
			return ret;
		}
	}
	else {
		cout << "Invalid switch. -e and -d allowed.";
		return 5;
	}
	return 0;
}




