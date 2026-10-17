--  SPDX-License-Identifier: Apache-2.0
--  Ada structural rule look-alikes. No line in this file may produce a finding.
with GNAT.OS_Lib; use GNAT.OS_Lib;
with Ada.Numerics.Discrete_Random;
with GNAT.MD5;
package body Safe is
   pragma Unsuppress (Index_Check);
   pragma Suppress (Elaboration_Check);

   function To_Bits is new Ada.Unchecked_Conversion (Float, Unsigned_32);
   function To_Addr is new Ada.Unchecked_Conversion (Node_Access, System.Address);

   package Rand is new Ada.Numerics.Discrete_Random (Positive);
   Gen : Rand.Generator;
   Global_Obj : aliased Buffer;
   Global_Ptr : Buffer_Access;
   Hits : Natural := 0 with Atomic;

   function C_Strlen (S : chars_ptr) return size_t;
   pragma Import (C, C_Strlen, "strlen");

   procedure On_Safe (X : int)
     with Export, Convention => C, External_Name => "on_safe";

   procedure On_Safe (X : int) is
   begin
      Handle (Integer (X));
   exception
      when E : others =>
         Report (E);
   end On_Safe;

   procedure Register is
   begin
      Global_Ptr := Global_Obj'Unchecked_Access;
   end Register;

   procedure Use_Local is
      Buf : aliased Buffer;
      P   : Buffer_Access := Buf'Unchecked_Access;
   begin
      Process (P);
   end Use_Local;

   Reg : Unsigned_32 with Address => System'To_Address (16#4000_0000#);

   procedure Freed (Title : String) is
      C_Title : chars_ptr := New_String (Title);
   begin
      C_Set_Title (C_Title);
      Free (C_Title);
   end Freed;

   procedure Run_Git (Args : Argument_List) is
      Ok  : Boolean;
      Git : String_Access := Locate_Exec_On_Path ("git");
   begin
      Spawn ("/usr/bin/git", Args, Ok);
      Spawn (Git.all, Args, Ok);
   end Run_Git;

   procedure Count_Users (Conn : Database_Connection; Age : Integer) is
   begin
      Execute (Conn, "SELECT * FROM users WHERE id = $1", Params => (1 => +Age));
      Execute (Conn, "SELECT count(*) FROM users WHERE age > " & Integer'Image (Age));
      Put_Line ("SELECT " & Integer'Image (Age));
   end Count_Users;

   procedure Prompt (Password : String) is
   begin
      Put_Line ("Password length:" & Natural'Image (Password'Length));
      Put_Line ("Enter password:");
   end Prompt;

   procedure Close_All (Obj : in out Handle) is
   begin
      raise Program_Error;
   end Close_All;

   procedure Shuffle (Deck : in out Cards) is
   begin
      Swap (Deck, 1, Rand.Random (Gen));
   end Shuffle;

   function Cache_Key (Location : String) return String is
   begin
      return GNAT.MD5.Digest (Location);
   end Cache_Key;

   procedure Single (Head : in out Node_Access) is
   begin
      Free (Head);
      Free (Head);
   end Single;

   task body Worker is
   begin
      loop
         Hits := Hits + 1;
      end loop;
   end Worker;
end Safe;
