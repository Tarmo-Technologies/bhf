! SPDX-License-Identifier: Apache-2.0
! A bind(C) record parser taking an assumed-size c_char buffer and its
! length by value (#235). It trusts the record's length byte over n.
module recs
  use iso_c_binding, only: c_char, c_int
  implicit none
  integer, public :: checksum = 0
contains
  ! A record: 'R', a length byte, then that many payload bytes. The length
  ! byte is trusted over n, the bytes the caller passed.
  subroutine parse_rec(buf, n) bind(C, name="parse_rec")
    integer(c_int), value :: n
    character(kind=c_char), dimension(*), intent(in) :: buf
    integer :: i, k
    if (n < 2) return
    if (buf(1) /= 'R') return
    k = ichar(buf(2))
    do i = 1, k
      checksum = checksum + ichar(buf(2 + i))
    end do
  end subroutine parse_rec
end module recs
