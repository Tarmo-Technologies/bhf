// SPDX-License-Identifier: Apache-2.0
package com.tarmo.acceptance;

import org.slf4j.helpers.MessageFormatter;

public final class Smoke {
    public static int checksum(byte[] data) throws java.io.IOException {
        String marker = System.getenv("BHF_ACCEPTANCE_MARKER");
        if (marker != null) {
            java.nio.file.Path path = java.nio.file.Path.of(marker);
            if (!java.nio.file.Files.exists(path)) {
                java.nio.file.Files.writeString(path, "checksum entered\n");
            }
        }
        return MessageFormatter.format("bytes {}", data.length).getMessage().length();
    }

    public static void main(String[] args) {
        String result = MessageFormatter.format("offline {}", "ready").getMessage();
        if (!"offline ready".equals(result)) {
            throw new AssertionError(result);
        }
        System.out.println(result);
    }
}
