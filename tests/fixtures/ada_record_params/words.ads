--  SPDX-License-Identifier: Apache-2.0
--  A dictionary entry as whitakers-words declares one: a constrained String
--  subtype, an enumeration and an integer in one record (#418).
package Words is
   subtype Eword is String (1 .. 24);
   type Part_Of_Speech_Type is (X, N, V, Adj);
   type Ewds_Record is record
      W    : Eword;
      Pofs : Part_Of_Speech_Type;
      Freq : Integer;
   end record;

   --  Reads an entry: the record is an `out` parameter.
   procedure Get (S : in String; P : out Ewds_Record; Last : out Integer);

   --  Weighs an entry: the record is an `in` parameter.
   function Weight (R : Ewds_Record) return Integer;
end Words;
