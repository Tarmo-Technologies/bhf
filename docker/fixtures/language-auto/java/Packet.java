// SPDX-License-Identifier: Apache-2.0
public final class Packet {
    public static int packetChecksum(byte[] data) {
        int result = 0;
        for (byte value : data) result = (result + (value & 255)) % 251;
        return result;
    }
}
