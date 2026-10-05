-- SPDX-License-Identifier: Apache-2.0
package body Packet is
   function Checksum (Data : String) return Natural is
      Result : Natural := 0;
   begin
      for Value of Data loop
         Result := (Result + Character'Pos (Value)) mod 251;
      end loop;
      return Result;
   end Checksum;
end Packet;
