-- SPDX-License-Identifier: Apache-2.0
local M = {}
function M.packet_checksum(data)
  local result = 0
  for i = 1, #data do result = (result + data:byte(i)) % 251 end
  return result
end
return M
