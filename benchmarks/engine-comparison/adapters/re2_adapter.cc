// SPDX-License-Identifier: Apache-2.0
// RE2 trade-study adapter (#371): compile the input as a regular expression
// (RE2's constructor runs re2::Regexp::Parse) under a memory budget, and
// match it against a fixed string when it compiles.
#include <cstddef>
#include <string>

#include "re2/re2.h"

extern "C" int target_one_input(const unsigned char *data, size_t size) {
    if (size > 4096) return 0;
    RE2::Options options;
    options.set_log_errors(false);
    options.set_max_mem(64 << 20);
    std::string pattern(reinterpret_cast<const char *>(data), size);
    RE2 re(pattern, options);
    if (re.ok()) {
        (void)RE2::PartialMatch("the quick brown fox 0123456789", re);
    }
    return 0;
}
