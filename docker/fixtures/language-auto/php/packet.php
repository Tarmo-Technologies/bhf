<?php
// SPDX-License-Identifier: Apache-2.0
function packet_checksum(string $data): int {
    $result = 0;
    for ($i = 0; $i < strlen($data); ++$i) $result = ($result + ord($data[$i])) % 251;
    return $result;
}
