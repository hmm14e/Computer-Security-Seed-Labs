/* Task5: Verifiying a Signature */
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
	BIGNUM *S = BN_new();
	BIGNUM *m = BN_new();

	//Initialize variables with given values
	BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
	BN_hex2bn(&e, "010001");
	BN_hex2bn(&S, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F");
	 
	/*Decrypt using Public Key
	/m = S^e mod n*/
	BN_mod_exp(m, S, e, n, ctx);
	printBNhex("message hex = ", m);


	return 0;
}
