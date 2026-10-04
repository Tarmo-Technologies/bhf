// SPDX-License-Identifier: Apache-2.0
package com.tarmo.acceptance;

import org.slf4j.helpers.MessageFormatter;

public final class Smoke {
    public static void main(String[] args) {
        String result = MessageFormatter.format("offline {}", "ready").getMessage();
        if (!"offline ready".equals(result)) {
            throw new AssertionError(result);
        }
        System.out.println(result);
    }
}
