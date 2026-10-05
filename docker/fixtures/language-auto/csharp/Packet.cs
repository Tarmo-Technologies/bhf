// SPDX-License-Identifier: Apache-2.0
public static class Packet {
    public static int PacketChecksum(byte[] data) {
        int result = 0;
        foreach (byte value in data) result = (result + value) % 251;
        return result;
    }
}
