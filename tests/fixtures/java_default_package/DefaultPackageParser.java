// SPDX-License-Identifier: Apache-2.0

public final class DefaultPackageParser {
    private DefaultPackageParser() {}

    public static void parse(byte[] data) {
        if (data.length > 0 && data[0] == 'G') {
            throw new IllegalStateException("default package target reached");
        }
    }
}
