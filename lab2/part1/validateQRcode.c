#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <stdlib.h>
#include "lib/encoding.h"

#include "lib/sha1.h"

#define KEY_BINARY_LEN 80
#define DIGITS_POWER 1000000

// Function to convert a HEX string to binary value in unsigened char variable
// reference: https://stackoverflow.com/questions/3408706/hexadecimal-string-to-byte-array-in-c
uint8_t* hexStr2Bytes(const char *hex_str){
	uint8_t bytearray_size = strlen(hex_str) / 2;
	uint8_t *bytearray = malloc(bytearray_size * sizeof(unsigned char));
	
	for (int i = 0; i < bytearray_size; i++)
	{
		sscanf(hex_str + 2 * i, "%02x", &bytearray[i]);
	}

	return bytearray;
}

// Function to truncate a hash value to 6 characters
// base on RFC docs page 12,13
int truncateHash(uint8_t *hash, int hashLength)
{
	// Calculate the offset from the last byte of the hash
	int offset = hash[hashLength - 1] & 0xF;

	// Calculate the binary value using the selected bytes
	int binary =
			((hash[offset] & 0x7F) << 24) |
			((hash[offset + 1] & 0xFF) << 16) |
			((hash[offset + 2] & 0xFF) << 8) |
			(hash[offset + 3] & 0xFF);

	// Calculate the truncated value by modulo dividing by 10^6
	int truncatedValue = binary % DIGITS_POWER;

	return truncatedValue;
}

// Function to perform XOR operation between two binary values
void xorBinary(const uint8_t *binary1, uint8_t *repeat_binary, uint8_t *result, size_t length)
{
	for (int i = 0; i < length; i++)
	{
		result[i] = binary1[i] ^ *repeat_binary; // Perform XOR with repeating value
	}
}

// calls the sha1 functions to hash the inner or outer key with a message
uint8_t *hash(uint8_t *key, int key_size, uint8_t *message, int m_size, uint8_t *sha)
{
	SHA1_INFO ctx;
	sha1_init(&ctx);

	sha1_update(&ctx, key, key_size);
	sha1_update(&ctx, message, m_size);

	sha1_final(&ctx, sha);

	return sha;
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	// key to binary
	uint8_t *secret_binary = hexStr2Bytes(secret_hex);
	uint8_t secret_binary_padded[SHA1_BLOCKSIZE];
	// pad 0s to the right of secret binary until it reaches 64 bytes
	memcpy(secret_binary_padded, secret_binary, strlen(secret_binary));
	memset(secret_binary_padded + strlen(secret_binary), 0, SHA1_BLOCKSIZE - strlen(secret_binary));

	// uint8_t *repeating_value1 = hexStr2Bytes("5c5c5c5c5c5c5c5c5c5c"); // inner pad
	// uint8_t *repeating_value2 = hexStr2Bytes("36363636363636363636"); // outer pad
	// printf("Repeating Value 1: %u\n", repeating_value1);
	// printf("Repeating Value 2: %u\n", repeating_value2);

	uint8_t outer_key[SHA1_BLOCKSIZE];
	xorBinary(secret_binary_padded, (uint8_t *) "\x5c", outer_key, SHA1_BLOCKSIZE);

	uint8_t inner_key[SHA1_BLOCKSIZE];
	xorBinary(secret_binary_padded, (uint8_t *) "\x36", inner_key, SHA1_BLOCKSIZE);

	// 30s timestamp message
	time_t current_time;
	current_time = time(NULL);
	time_t T = current_time / 30;
	uint8_t time_binary[8];
	for (int i = 7; i >= 0; i--)
	{
		time_binary[i] = T;
		T >>= 8;
	}

	uint8_t inner_hash[SHA1_DIGEST_LENGTH];
	hash(inner_key, SHA1_BLOCKSIZE, time_binary, 8, inner_hash);

	SHA1_INFO ctx2;
	uint8_t outer_hash[SHA1_DIGEST_LENGTH];
	hash(outer_key, SHA1_BLOCKSIZE, inner_hash, SHA1_DIGEST_LENGTH, outer_hash);

	int output = truncateHash(outer_hash, SHA1_DIGEST_LENGTH);

	if (output == atoi(TOTP_string))
		return 1;
	else
		return 0;
}


int
main(int argc, char * argv[])
{
	if ( argc != 3 ) {
		printf("Usage: %s [secretHex] [TOTP]\n", argv[0]);
		return(-1);
	}

	char *	secret_hex = argv[1];
	char *	TOTP_value = argv[2];

	assert (strlen(secret_hex) <= 20);
	assert (strlen(TOTP_value) == 6);

	printf("\nSecret (Hex): %s\nTOTP Value: %s (%s)\n\n",
		secret_hex,
		TOTP_value,
		validateTOTP(secret_hex, TOTP_value) ? "valid" : "invalid");

	return(0);
}
