// SPDX-License-Identifier: Apache-2.0
public final class Checksum {
    public static int checksum(byte[] data) {
        int sum = 0;
        for (byte value : data) {
            sum = (sum + (value & 0xff)) & 0xffff;
        }
        return sum;
    }
}
