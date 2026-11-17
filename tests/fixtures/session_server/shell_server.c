// SPDX-License-Identifier: Apache-2.0
//
// A length-framed TCP service for the session lane's runtime-oracle test
// (#364). Every request and reply is preceded by a big-endian u16 length. RUN
// (op 1, a u16 data length, the data) builds a shell command from the data
// and passes it to system(): a planted command injection (CWE-78). Built with
// -DCLEAN it only counts the data. Before it serves, it creates a
// world-writable directory (argv[2]): an insecure-permissions event of its
// start-up, which no session caused.
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
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

static unsigned char run(const unsigned char *frame, size_t n) {
  if (n < 3 || frame[0] != 1) return 1;
  size_t len = (size_t)frame[1] << 8 | frame[2];
  if (len > n - 3 || len > 200) return 1;
#ifdef CLEAN
  return (unsigned char)len;
#else
  char command[256];
  snprintf(command, sizeof command, "echo %.*s > /dev/null", (int)len, (const char *)frame + 3);
  return (unsigned char)system(command); /* the planted injection */
#endif
}

int main(int argc, char **argv) {
  if (argc < 3) {
    fprintf(stderr, "usage: shell_server PORT STARTUP_DIR\n");
    return 2;
  }
  umask(0);
  mkdir(argv[2], 0777);
  int s = socket(AF_INET, SOCK_STREAM, 0);
  int one = 1;
  setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof addr);
  addr.sin_family = AF_INET;
  addr.sin_port = htons((unsigned short)atoi(argv[1]));
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (bind(s, (struct sockaddr *)&addr, sizeof addr) != 0 || listen(s, 8) != 0) {
    perror("shell_server: bind");
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
      unsigned char reply[3] = {0, 1, run(frame, n)};
      if (write(c, reply, sizeof reply) != (ssize_t)sizeof reply) break;
    }
    close(c);
  }
}
