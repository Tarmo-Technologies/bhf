--  SPDX-License-Identifier: Apache-2.0
package body Words is
   procedure Get (S : in String; P : out Ewds_Record; Last : out Integer) is
   begin
      P.W := (others => ' ');
      P.Pofs := X;
      P.Freq := 0;
      Last := S'First - 1;
      if S'Length > 0 and then S (S'First) = 'N' then
         P.Pofs := N;
         Last := S'First;
      end if;
   end Get;

   function Weight (R : Ewds_Record) return Integer is
      Table : constant array (1 .. 4) of Integer := (1, 2, 3, 4);
   begin
      --  Planted: an adjective's frequency indexes the table unchecked.
      if R.Pofs = Adj and then R.W (1) /= ' ' then
         return Table (R.Freq);
      end if;
      return Part_Of_Speech_Type'Pos (R.Pofs);
   end Weight;
end Words;
