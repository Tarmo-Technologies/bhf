// SPDX-License-Identifier: Apache-2.0
// The full image's C++ MemorySanitizer replay finds the planted read: a heap
// field the parser writes only for a nonzero first byte, then branches on.
#include <cstddef>
#include <cstdio>
#include <string>

int parse_record(const unsigned char *data, size_t len) {
  if (len < 1) return 0;
  std::string tag(reinterpret_cast<const char *>(data), len);
  int *fields = new int[4];
  int large = 0;
  if (tag[0] != 0) fields[1] = tag[0];
  if (fields[1] > 3) {
    std::puts("large record");
    large = 1;
  }
  delete[] fields;
  return large;
}
