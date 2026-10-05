# SPDX-License-Identifier: Apache-2.0
package Packet;
use strict;
use warnings;
sub packet_checksum {
    my ($data) = @_;
    return unpack('%32C*', $data) % 251;
}
1;
