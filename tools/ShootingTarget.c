#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
  printf("Start outputting\n");

  int i = 0;
  while (1) {
    printf(">> %04d", i++);
    fflush(stdout);

    sleep(2);
  }

  return 0;
}