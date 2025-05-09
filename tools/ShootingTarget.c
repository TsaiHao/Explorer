#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
  printf("Start outputting\n");

  pid_t self_pid = getpid();

  int i = 0;
  while (1) {
    printf("[%d] >> %04d iteration\n", self_pid, i++);
    fflush(stdout);

    sleep(2);
  }

  return 0;
}