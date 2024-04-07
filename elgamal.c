#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>
#include <time.h>

// Struct for ElGamal public key
typedef struct
{
	mpz_t prime_modulus; // Prime modulus (p)
	mpz_t generator;	 // Generator (g)
	mpz_t public_key;	 // Public key (y)
} ElGamalPublicKey;

// Struct for ElGamal private key
typedef struct
{
	mpz_t private_key; // Private key (x)
} ElGamalPrivateKey;

// Struct for ElGamal key pair
typedef struct
{
	ElGamalPublicKey public_key;   // Public key
	ElGamalPrivateKey private_key; // Private key
} ElGamalKeyPair;

typedef struct _ElGamalCiphertext
{
	mpz_t c1;
	mpz_t c2;
} ElGamalCiphertext;

// Define the size of the key (100 bit key)
#define KEY_SIZE 1024

// Translates to:
// "All I know is that to me, you look like you're lots of fun, open up your lovin' arms, watch out here I come!"
// (You Spin Me Right Round (Like A Record) by Dead or Alive, 1984)
#define MSG_TO_ENCRYPT "416C6C2049206B6E6F77206973207468617420746F206D652C20796F75206C6F6F6B206C696B6520796F75277265206C6F7473206F662066756E2C206F70656E20757020796F7572206C6F76696E272061726D732C207761746368206F75742068657265204920636F6D6521"

// Function to convert hexadecimal string to ASCII
void hexToAscii(const char *hexString, char *asciiString) {
    size_t len = strlen(hexString);
    if (len % 2 != 0) {
        fprintf(stderr, "Invalid hexadecimal string length\n");
        return;
    }

    size_t asciiLen = len / 2;
    for (size_t i = 0; i < asciiLen; i++) {
        sscanf(hexString + 2 * i, "%2hhx", &asciiString[i]);
    }
    asciiString[asciiLen] = '\0';
}

// Function to generate ElGamal key pair
void ElGamal_Gen(ElGamalKeyPair *key_pair, unsigned int key_size)
{
	// Initialize variables
	mpz_t tmp;
	gmp_randstate_t state;

	// Initialize variables
	mpz_init(tmp);
	gmp_randinit_default(state);

	// Set the random seed
	srand(time(NULL));
	gmp_randseed_ui(state, rand());

	// Generate a large prime number prime_modulus
	mpz_init(key_pair->public_key.prime_modulus);
	mpz_urandomb(tmp, state, key_size);
	mpz_nextprime(key_pair->public_key.prime_modulus, tmp);

	// Generate a random number private_key in the range [2, prime_modulus-2]
	mpz_init(key_pair->private_key.private_key);
	mpz_sub_ui(tmp, key_pair->public_key.prime_modulus, 2);
	mpz_urandomm(key_pair->private_key.private_key, state, tmp);
	mpz_add_ui(key_pair->private_key.private_key, key_pair->private_key.private_key, 2);

	// Generate a random number generator in the range [2, prime_modulus-2]
	mpz_init(key_pair->public_key.generator);
	mpz_urandomm(key_pair->public_key.generator, state, tmp);
	mpz_add_ui(key_pair->public_key.generator, key_pair->public_key.generator, 2);

	// Compute public_key->public_key = generator^private_key->private_key mod prime_modulus
	mpz_init(key_pair->public_key.public_key);
	mpz_powm(key_pair->public_key.public_key, key_pair->public_key.generator, key_pair->private_key.private_key, key_pair->public_key.prime_modulus);

	// Clear memory
	mpz_clear(tmp);
	gmp_randclear(state);
}

// Function to encrypt a message using ElGamal
void ElGamal_Encrypt(const mpz_t message, const ElGamalPublicKey *public_key, ElGamalCiphertext *ciphertext)
{
	// Initialize variables
	mpz_t k, tmp;
	gmp_randstate_t state;

	// Initialize variables
	mpz_inits(k, tmp, ciphertext->c1, ciphertext->c2, NULL);
	gmp_randinit_default(state);

	// Generate a random number k in the range [2, prime_modulus-2]
	mpz_sub_ui(tmp, public_key->prime_modulus, 2);
	mpz_urandomm(k, state, tmp);
	mpz_add_ui(k, k, 2);

	// Compute c1 = generator^k mod prime_modulus
	mpz_powm(ciphertext->c1, public_key->generator, k, public_key->prime_modulus);

	// Compute c2 = message * public_key->public_key^k mod prime_modulus
	mpz_powm(tmp, public_key->public_key, k, public_key->prime_modulus);
	mpz_mul(ciphertext->c2, tmp, message);
	mpz_mod(ciphertext->c2, ciphertext->c2, public_key->prime_modulus);

	// Clear memory
	mpz_clears(k, tmp, NULL);
	gmp_randclear(state);
}

// Function to decrypt a ciphertext using ElGamal
void ElGamal_Decrypt(const ElGamalCiphertext *ciphertext, const ElGamalPrivateKey *private_key, const ElGamalPublicKey *public_key, mpz_t message) {
    // Compute s = c1^x mod prime_modulus
    mpz_t s;
    mpz_init(s);
    mpz_powm(s, ciphertext->c1, private_key->private_key, public_key->prime_modulus);

    // Compute s_inverse = inverse of s mod prime_modulus
    mpz_t s_inverse;
    mpz_init(s_inverse);
    mpz_invert(s_inverse, s, public_key->prime_modulus);

    // Compute message = c2 * s_inverse mod prime_modulus
    mpz_mul(message, ciphertext->c2, s_inverse);
    mpz_mod(message, message, public_key->prime_modulus);

    // Clear memory
    mpz_clears(s, s_inverse, NULL);
}

int main() {

    // Initialize key pair
    ElGamalKeyPair key_pair;
    ElGamal_Gen(&key_pair, KEY_SIZE);

    // Convert message to mpz_t
    mpz_t message;
    mpz_init(message);
	mpz_set_str(message, MSG_TO_ENCRYPT, 16);

	// Print the plaintext message
	char asciiMessage[256] = {0};
	hexToAscii(MSG_TO_ENCRYPT, asciiMessage);
	printf("\nPlaintext Message (Hexadecimal):\n%s\n", MSG_TO_ENCRYPT);
	printf("Plaintext Message (ASCII):\n%s\n", asciiMessage);

    // Print keys
    printf("Public Key:\n");
    gmp_printf("Prime Modulus (p): %Zd\n", key_pair.public_key.prime_modulus);
    gmp_printf("Generator (g): %Zd\n", key_pair.public_key.generator);
    gmp_printf("Public Key (y): %Zd\n", key_pair.public_key.public_key);
    printf("\nPrivate Key:\n");
    gmp_printf("Private Key (x): %Zd\n", key_pair.private_key.private_key);

    // Encrypt message
    ElGamalCiphertext ciphertext;
    ElGamal_Encrypt(message, &key_pair.public_key, &ciphertext);

    // Print encrypted text
    printf("\nEncrypted Text (c1, c2):\n");
    gmp_printf("(%Zd, %Zd)\n", ciphertext.c1, ciphertext.c2);

    // Decrypt ciphertext
    mpz_t decrypted_message;
    mpz_init(decrypted_message);
    ElGamal_Decrypt(&ciphertext, &key_pair.private_key, &key_pair.public_key, decrypted_message);

    // Print decrypted message
    printf("\nDecrypted Message:\n");
    gmp_printf("%Zd\n", decrypted_message);

	char decryptedAsciiMessage[256] = {0};
	mpz_get_str(decryptedAsciiMessage, 16, decrypted_message);
	decryptedAsciiMessage[256] = '\0';
	printf("\nDecrypted Message (Hexadecimal):\n%s\n", decryptedAsciiMessage);

	char asciiDecryptedMessage[256] = {0};
	hexToAscii(decryptedAsciiMessage, asciiDecryptedMessage);
	printf("\nDecrypted Message (ASCII):\n%s\n", asciiDecryptedMessage);

	if (strcmp(asciiMessage, asciiDecryptedMessage) == 0) {
		printf("\nDecrypted message matches original message!\n");
	} else {
		printf("\nDecrypted message does not match original message!\n");
	}

    // Clear memory
    mpz_clear(message);
    mpz_clear(decrypted_message);
    mpz_clears(ciphertext.c1, ciphertext.c2, NULL);

    return 0;
}