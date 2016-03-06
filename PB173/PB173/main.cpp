

#include <cstring>
#include <string>
#include <iostream>
#include <fstream>

#include "crypto.h"

using namespace std;


int main(int argc, const char ** argv) {
	if (argc != 5) return 1;

	int ret = 0;


	if (std::string("-e").compare(argv[1]) == 0) {
		ifstream ifile;
		fstream ofile;

		ifile.open(argv[3], fstream::in | fstream::binary);
		ofile.open(argv[4], fstream::out | fstream::binary);

		try {
			encryptAndHash(ifile, ofile, argv[2]);
		}
		catch (CryptoException & e) {
			cout << e.what() << endl;
			ret = 1;
		}

		ifile.close();
		ofile.close();
	}
	else if (std::string("-d").compare(argv[1]) == 0) {
		ifstream ifile;
		ofstream ofile;
		ifile.open(argv[3], fstream::in | fstream::binary);
		ofile.open(argv[4], fstream::out | fstream::binary);

		try {
			int ret = decryptAndVerify(ifile, ofile, argv[2]);
		}
		catch (CryptoVerifycationException & e) {
			cout << e.what() << endl;
			ofile.close();
			ofile.open(argv[4], fstream::out | fstream::binary);
			ret = 2;
		}
		catch (CryptoException & e) {
			cout << e.what() << endl;
			ret = 1;
		}

		ifile.close();
		ofile.close();
	}
	else {
		cout << "Invalid switch. -e and -d allowed.";
		ret = 3;
	}
	return ret;
}




