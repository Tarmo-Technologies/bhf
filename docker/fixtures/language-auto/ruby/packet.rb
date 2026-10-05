# SPDX-License-Identifier: Apache-2.0
module Packet
  def self.packet_checksum(data)
    data.bytes.sum % 251
  end
end
