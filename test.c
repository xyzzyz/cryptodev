#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>

#include "cryptiface.h"

void hexdump(const void *ptr, int buflen) {
  unsigned char *buf = (unsigned char*)ptr;
  int i, j;
  for (i=0; i<buflen; i+=16) {
    printf("%06x: ", i);
    for (j=0; j<16; j++)
      if (i+j < buflen)
        printf("%02x ", buf[i+j]);
      else
        printf("   ");
    printf(" ");
    for (j=0; j<16; j++)
      if (i+j < buflen)
        printf("%c", isprint(buf[i+j]) ? buf[i+j] : '.');
    printf("\n");
  }
}

int
main(int argc, char **argv) {
  int fd = open("/dev/cryptiface", O_RDWR);
  if(-1 == fd) {
    perror("open()");
    return -1;
  }
  int key_id = cryptiface_addkey(fd, CRYPTIFACE_ALG_DES, "DEADBABEDEADBEEF");
  if(-1 == key_id) {
    perror("cryptiface_addkey()");
    return -1;
  }

  if(cryptiface_setcurrent(fd, CRYPTIFACE_ALG_DES, key_id, true)) {
    perror("cryptiface_setcurrent()");
    return -1;
  }

  const char data[] = "LOL WAT CO JA WIDZAM\n";
  printf("plaintext:\n");
  hexdump(data, sizeof(data));

  if(write(fd, data, sizeof(data)) < 0) {
    perror("write()");
    return -1;
  }

  printf("cryptiface_numresults() = %d\n", cryptiface_numresults(fd));
  char buf[10*sizeof(data)];
  ssize_t len = read(fd, buf, sizeof(buf));
  if(len < 0) {
    perror("read()");
    return -1;
  }
  printf("encrypted:\n");
  hexdump(buf, len);

  if(cryptiface_setcurrent(fd, CRYPTIFACE_ALG_DES, key_id, false)) {
    perror("cryptiface_setcurrent()");
    return -1;
  }

  if(write(fd, buf, len) < 0) {
    perror("write()");
    return -1;
  }

  char clear_buf[sizeof(buf)];
  len = read(fd, clear_buf, sizeof(clear_buf));
  if(len < 0) {
    perror("read()");
    return -1;
  }
  printf("decrypted:\n");
  hexdump(clear_buf, len);

  return 0;
}
