#include <stdio.h>
#include <stdlib.h>


int main( int argc, char *argv[] )
{

  FILE *fp;
  char path[1035];

  /* Open the command for reading. */
  fp = popen("/bin/echo 'Arch: ' $(uname -m); /bin/cat /etc/*-release | /bin/grep ^ID=; /bin/grep MemFree /proc/meminfo; /bin/grep MemTotal /proc/meminfo;"
, "r");
  if (fp == NULL) {
    printf("Failed to run command\n" );
    exit(1);
  }

  /* Read the output a line at a time - output it. */
  while (fgets(path, sizeof(path), fp) != NULL) {
    printf("%s", path);
  }

  /* close */
  pclose(fp);

  return 0;
}