// SPDX-License-Identifier: Apache-2.0
#include <cstddef>
#include <string>
#include <vector>

#include "tokens.hpp"

namespace {

std::vector<std::string> split(const unsigned char *data, size_t len) {
    std::vector<std::string> tokens(1);
    for (size_t i = 0; i < len; ++i) {
        if (data[i] == ',') {
            tokens.emplace_back();
        } else {
            tokens.back().push_back(static_cast<char>(data[i]));
        }
    }
    return tokens;
}

}  // namespace

/* Counts the tokens of a comma-separated record and reads the weight the
 * first token names. A weight index taken from the record is checked against
 * the token count, not the weight table's size. */
int score_tokens(const unsigned char *data, size_t len) {
    static const int weights[4] = {1, 2, 3, 5};
    std::vector<std::string> tokens = split(data, len);
    if (tokens.size() < 2 || tokens[0] != "T") {
        return 0;
    }
    size_t index = tokens.size();
    return weights[index];
}
