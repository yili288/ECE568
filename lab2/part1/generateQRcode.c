#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Function to convert a HEX string to BINARY value as unsigned char variable
uint8_t* hexStr2Bytes(const char *hex_str){
	uint8_t bytearray_size = strlen(hex_str) / 2;
	uint8_t *bytearray = malloc(bytearray_size * sizeof(unsigned char));

	for (int i = 0; i < bytearray_size; i++)
	{
		sscanf(hex_str + 2 * i, "%02x", &bytearray[i]);
	}
	return bytearray;
}

int
main(int argc, char * argv[])
{
	if ( argc != 4 ) {
		printf("Usage: %s [issuer] [accountName] [secretHex]\n", argv[0]);
		return(-1);
	}

	char *	issuer = argv[1];
	char *	accountName = argv[2];
	char *	secret_hex = argv[3];

	assert (strlen(secret_hex) <= 20);

	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, secret_hex);

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator

    int secret_len = strlen(secret_hex); // always 20

	// convert initial hex to binary for passing into base32_encode
	char* decoded_base32 = hexStr2Bytes(secret_hex);
	
    // printf("decoded_base32: %s\n", decoded_base32);
	// printf("decoded_base32 len: %d\n", strlen(decoded_base32)); // this is length 80

    uint8_t encoded_base32[16];

	// Feed in decoded_base32 of len %d and getting output of len 16 (80/5)
    base32_encode(decoded_base32, strlen(decoded_base32), encoded_base32, 16);

    // printf("encoded_base32: %s\n", encoded_base32);
	// printf("encoded_base32 len: %d\n", strlen(encoded_base32));
    
	//  otpauth://totp/ACCOUNTNAME?issuer=ISSUER&secret=SECRET&period=30
	char uri[100] = "otpauth://totp/"; // make large enough to hold entire uri
	// printf("%s\n", uri);
	strcat(uri, urlEncode(accountName));
	// printf("%s\n", uri);
	strcat(uri, "?issuer=");
	// printf("%s\n", uri);
	strcat(uri, urlEncode(issuer)); // need to encode special chars with %20
	// printf("%s\n", uri);
	strcat(uri, "&secret=");
	// printf("%s\n", uri);
	strcat(uri, urlEncode(encoded_base32));
	// printf("%s\n", uri);
	strcat(uri, "&period=30");

	// printf("%s\n", uri);

	displayQRcode(uri);

    // char correct_uri[] = "otpauth://totp/gibson?issuer=ECE568&secret=CI2FM6EQCI2FM6EQ&period=30";
    // displayQRcode(correct_uri);
	// displayQRcode("otpauth://testing");

	return (0);
}
