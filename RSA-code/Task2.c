﻿/* Task2: Finding private key d */
#include <stdio.h>
#include <openssl/bn.h>

#define NBITS 256

void printBNhex(char *msg, BIGNUM * a)
{
	/* Use BN_bn2hex(a) for hex string*/
	char * number_str = BN_bn2hex(a);
	printf("%s %s\n", msg, number_str);
	OPENSSL_free(number_str);
}

int main ()
{
	//Declare variables
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *e = BN_new();
	BIGNUM *n = BN_new();
	BIGNUM *M = BN_new();
	BIGNUM *c = BN_new();
	BIGNUM *d = BN_new();

	//Initialize variables with given values
	BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
	BN_hex2bn(&e, "010001");
	BN_hex2bn(&M, "4120746f702073656372657421");
	BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
	
	//Encrypt -> c = M^e mod n 
	BN_mod_exp(c, M, e, n, ctx);
	printBNhex("encryption of message = ", c);
	
	//Decrypt -> M = c^d mod n
	BN_mod_exp(M, c, d, n, ctx);
	printBNhex("decryption of message = ", M);

	return 0;
}
