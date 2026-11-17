// SPDX-License-Identifier: Apache-2.0
//
// A length-framed TCP command service for the session lane's coverage test
// (#363). Every request and reply is preceded by a big-endian u16 length. A
// request is a command byte, a u16 data length and the data; each command
// and each class of data runs its own code, and none of it has a bug. Built
// with SanitizerCoverage and c_runtime/bhf_service_cov.c, it reports which
// of that code a session reached.
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

static unsigned char classify(const unsigned char *data, size_t len) {
  if (len == 0) return 0;
  if (data[0] < 32) return 1;
  if (data[0] < 64) return 2;
  if (data[0] < 128) return data[len - 1] & 1 ? 3 : 4;
  return len > 4 ? 5 : 6;
}

static unsigned char command(const unsigned char *frame, size_t n) {
  if (n < 3) return 0xff;
  size_t len = (size_t)frame[1] << 8 | frame[2];
  if (len > n - 3) return 0xfe;
  const unsigned char *data = frame + 3;
  switch (frame[0] & 7) {
  case 0: return 0;
  case 1: return classify(data, len);
  case 2: return (unsigned char)(len * 3);
  case 3: return len > 2 && data[1] == 'S' ? 7 : 8;
  case 4: return len ? (unsigned char)(data[0] ^ 0x5a) : 9;
  case 5: return len > 8 ? 10 : 11;
  case 6: return frame[0] > 100 ? 12 : 13;
  default: return classify(data, len) + 20;
  }
}

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: command_server PORT\n");
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
    perror("command_server: bind");
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
      unsigned char reply[3] = {0, 1, command(frame, n)};
      if (write(c, reply, sizeof reply) != (ssize_t)sizeof reply) break;
    }
    close(c);
  }
}
