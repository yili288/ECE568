#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
    printf("secret_hex len: %d\n", secret_len);

    // char decoded_base32[20] = {'\0'}; // right way to initialize result array?
    uint8_t decoded_base32[20];
    base32_decode(secret_hex, decoded_base32, 20); // convert from hex to binary first

    printf("decoded_base32: %s\n", decoded_base32);

    // char encoded_base32[80] = {'\0'}; // right way to initialize result array?
    uint8_t encoded_base32[80];
    base32_encode(decoded_base32, secret_len, encoded_base32, 80);

    printf("encoded_base32: %s\n", encoded_base32);
    
	//  otpauth://totp/ACCOUNTNAME?issuer=ISSUER&secret=SECRET&period=30
	char uri[] = "otpauth://totp/";
	printf("%s\n", uri);
	strcat(uri, urlEncode(accountName));
	printf("%s\n", uri);
	strcat(uri, "?issuer=");
	printf("%s\n", uri);
	strcat(uri, urlEncode(issuer));
	printf("%s\n", uri);
	strcat(uri, "&secret=");
	printf("%s\n", uri);
	strcat(uri, encoded_base32);
	printf("%s\n", uri);
	strcat(uri, "&period=30");

	printf("%s\n", uri);

	displayQRcode(uri);

    // char correct_uri[] = "otpauth://totp/gibson?issuer=ECE568&secret=CI2FM6EQCI2FM6EQ&period=30";
    // displayQRcode(correct_uri);
	// displayQRcode("otpauth://testing");

	return (0);
}
