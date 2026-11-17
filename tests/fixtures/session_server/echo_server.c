// SPDX-License-Identifier: Apache-2.0
//
// A length-framed TCP service for the session lane's --session-server-cmd
// test (#260). Every request and reply is preceded by a big-endian u16
// length. ECHO (op 1, a u16 data length, the data) copies its data into an
// 8-byte heap buffer: data longer than 8 bytes is a planted
// heap-buffer-overflow (CWE-122), which ASan reports as the service exits.
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int read_full(int fd, unsigned char *buf, size_t n) {
  size_t got = 0;
  while (got < n) {
    ssize_t r = read(fd, buf + got, n - got);
    if (r <= 0) return -1;
    got += (size_t)r;
  }
  return 0;
}

static unsigned char echo(const unsigned char *frame, size_t n) {
  if (n < 3 || frame[0] != 1) return 1;
  size_t len = (size_t)frame[1] << 8 | frame[2];
  if (len == 0 || len > n - 3) return 1;
  char *copy = malloc(8);
  memcpy(copy, frame + 3, len); /* the planted overflow */
  unsigned char first = (unsigned char)copy[0];
  free(copy);
  return first;
}

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: echo_server PORT\n");
    return 2;
  }
  int s = socket(AF_INET, SOCK_STREAM, 0);
  int one = 1;
  setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof addr);
  addr.sin_family = AF_INET;
  addr.sin_port = htons((unsigned short)atoi(argv[1]));
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (bind(s, (struct sockaddr *)&addr, sizeof addr) != 0 || listen(s, 8) != 0) {
    perror("echo_server: bind");
    return 1;
  }
  for (;;) {
    int c = accept(s, NULL, NULL);
    if (c < 0) continue;
    for (;;) {
      unsigned char header[2], frame[1024];
      if (read_full(c, header, 2) != 0) break;
      size_t n = (size_t)header[0] << 8 | header[1];
      if (n > sizeof frame || read_full(c, frame, n) != 0) break;
      unsigned char reply[3] = {0, 1, echo(frame, n)};
      if (write(c, reply, sizeof reply) != (ssize_t)sizeof reply) break;
    }
    close(c);
  }
}
