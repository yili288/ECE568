#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Function to convert a single hexadecimal digit to its binary equivalent
char* hex_digit_to_bin(char hex_digit) {
    switch(hex_digit) {
        case '0': return "0000";
        case '1': return "0001";
        case '2': return "0010";
        case '3': return "0011";
        case '4': return "0100";
        case '5': return "0101";
        case '6': return "0110";
        case '7': return "0111";
        case '8': return "1000";
        case '9': return "1001";
        case 'a': case 'A': return "1010";
        case 'b': case 'B': return "1011";
        case 'c': case 'C': return "1100";
        case 'd': case 'D': return "1101";
        case 'e': case 'E': return "1110";
        case 'f': case 'F': return "1111";
        default: return NULL; // Invalid hexadecimal digit
    }
}

// Function to convert a hexadecimal string to binary
char* hex_to_bin(const char* hex_string) {
    size_t hex_len = strlen(hex_string);
    size_t bin_len = hex_len * 4; // 4 bits for each hexadecimal digit

    // Allocate memory for binary string
    char* binary_string = (char*)malloc(bin_len + 1); // +1 for null terminator
    // if (binary_string == NULL) {
    //     perror("Memory allocation failed");
    //     exit(EXIT_FAILURE);
    // }

    // Convert each hexadecimal digit to binary and concatenate
    for (size_t i = 0; i < hex_len; i++) {
        char* bin = hex_digit_to_bin(hex_string[i]);
        // if (bin == NULL) {
        //     fprintf(stderr, "Invalid hexadecimal digit: %c\n", hex_string[i]);
        //     free(binary_string);
        //     exit(EXIT_FAILURE);
        // }
        strcat(binary_string, bin);
    }

    return binary_string;
}

// int main() {
//     const char* hex_string = "1A3F"; // Example hexadecimal string
//     char* binary_string = hex_to_bin(hex_string);
//     printf("Hexadecimal: %s\n", hex_string);
//     printf("Binary: %s\n", binary_string);
//     free(binary_string); // Free allocated memory
//     return 0;
// }

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

    int secret_len = strlen(secret_hex);
    printf("secret_hex len: %d\n", secret_len);
	char* binary_secret = hex_to_bin(secret_hex); // convert from hex to binary first

    char encoded_binary[100] = {'\0'};
    base32_encode(binary_secret, secret_len, encoded_binary, 100);

    printf("encoded_binary: %s\n", encoded_binary);
	//  otpauth://totp/ACCOUNTNAME?issuer=ISSUER&secret=SECRET&period=30
	char uri[] = "otpauth://totp/";
	printf("%s\n", uri);
	strcat(uri, accountName);
	printf("%s\n", uri);
	strcat(uri, "?issuer=");
	printf("%s\n", uri);
	strcat(uri, issuer);
	printf("%s\n", uri);
	strcat(uri, "&secret=");
	printf("%s\n", uri);
	strcat(uri, encoded_binary);
	printf("%s\n", uri);
	strcat(uri, "&period=30");

	free(binary_secret);

	printf("%s\n", uri);

	displayQRcode(uri);
    
    // char correct_uri[] = "otpauth://totp/gibson?issuer=ECE568&secret=CI2FM6EQCI2FM6EQ&period=30";
    // displayQRcode(correct_uri);
	// displayQRcode("otpauth://testing");

	return (0);
}
