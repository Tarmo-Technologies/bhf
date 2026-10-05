! SPDX-License-Identifier: Apache-2.0
subroutine packet_checksum(data, result)
  implicit none
  character(len=*), intent(in) :: data
  integer, intent(out) :: result
  integer :: i
  result = 0
  do i = 1, len(data)
    result = modulo(result + iachar(data(i:i)), 251)
  end do
end subroutine packet_checksum
