/* Task1: Finding private key d */
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
	BIGNUM *p = BN_new();
	BIGNUM *q = BN_new();
	BIGNUM *e = BN_new();
	BIGNUM *pheN = BN_new();
	BIGNUM *n = BN_new();
	BIGNUM *d = BN_new();
	BIGNUM *one = BN_new();


	//initialize variables with given values
	BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
	BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
	BN_hex2bn(&e, "0D88C3");
	BN_dec2bn(&one, "1");

	// n = p*q
	BN_mul(n, p, q, ctx);
	printBNhex("n = ", n);
	
	//phe(n)=(p-1)*(q-1)
	BN_sub(p, p, one);
	BN_sub(q, q, one);
	BN_mul(pheN, p, q, ctx);
	printBNhex("Phe(n) = ", pheN);

	//calculate d
	BN_mod_inverse(d, e, pheN, ctx); 
	printBNhex("PRIVATE KEY d = ", d);

	return 0;
}
