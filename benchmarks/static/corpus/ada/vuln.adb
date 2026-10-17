--  SPDX-License-Identifier: Apache-2.0
--  Ada structural rule positives (BHF-409..412, 419, 422, 428, 436, 437,
--  550, 564..571). Each EXPECT line must produce exactly that finding.
with GNAT.Sockets; use GNAT.Sockets;
with Ada.Numerics.Discrete_Random;
with GNAT.MD5;
package body Vuln is
   pragma Suppress (Index_Check);                       --  EXPECT BHF-564
   pragma Suppress (Overflow_Check);                    --  EXPECT BHF-565

   type Node_Access is access all Node;
   function To_Node is new Ada.Unchecked_Conversion (System.Address, Node_Access); --  EXPECT BHF-409
   procedure Free is new Ada.Unchecked_Deallocation (Node, Node_Access);

   package Rand is new Ada.Numerics.Discrete_Random (Character);
   Gen : Rand.Generator;
   Global_Ptr : Buffer_Access;
   Count : Natural := 0;

   procedure C_Strcpy (D, S : chars_ptr);
   pragma Import (C, C_Strcpy, "strcpy");               --  EXPECT BHF-568

   procedure On_Event (X : int)
     with Export, Convention => C, External_Name => "on_event";

   procedure On_Event (X : int) is                      --  EXPECT BHF-570
   begin
      Handle (Integer (X));
   end On_Event;

   procedure Store is
      Buf : aliased Buffer;
   begin
      Global_Ptr := Buf'Unchecked_Access;               --  EXPECT BHF-566
   end Store;

   procedure Decode (Data : Stream_Element_Array) is
      Header : Header_Record with Import, Address => Data'Address; --  EXPECT BHF-567
   begin
      Use_Header (Header);
   end Decode;

   procedure Set_Title (Title : String) is
      C_Title : chars_ptr := New_String (Title);        --  EXPECT BHF-550
   begin
      C_Set_Title (C_Title);
   end Set_Title;

   procedure Run_Tool (Tool : Config) is
      Ok : Boolean;
   begin
      Spawn (Tool.Program.all, No_Args, Ok);            --  EXPECT BHF-412
   end Run_Tool;

   procedure Find (Conn : Database_Connection; Who : String) is
      C : Forward_Cursor;
   begin
      C.Fetch (Conn, "SELECT * FROM users WHERE login = '" & Who & "'"); --  EXPECT BHF-419
   end Find;

   procedure Login (Account : String; Password : String) is
   begin
      Log.Debug ("Login {0} with {1}", Account, Password); --  EXPECT BHF-569
   end Login;

   overriding procedure Finalize (Obj : in out Handle) is
   begin
      if Obj.Fd < 0 then
         raise Program_Error;                           --  EXPECT BHF-571
      end if;
   end Finalize;

   procedure Serve (Sock : Socket_Type) is
      Channel : constant Stream_Access := Stream (Sock);
      Request : constant String := String'Input (Channel); --  EXPECT BHF-436
   begin
      Dispatch (Request);
   end Serve;

   function New_Session_Token return Character is
   begin
      return Rand.Random (Gen);                         --  EXPECT BHF-428
   end New_Session_Token;

   function Hash_Password (Password : String) return String is
   begin
      return GNAT.MD5.Digest (Password);                --  EXPECT BHF-422
   end Hash_Password;

   procedure Drop (Head : in out Node_Access) is
      Saved : Node_Access := Head;
   begin
      Free (Head);
      Free (Saved);                                     --  EXPECT BHF-410
   end Drop;

   procedure Peek (Head : in out Node_Access) is
      Cur : Node_Access := Head;
   begin
      Free (Head);
      Show (Cur.Label);                                 --  EXPECT BHF-437
   end Peek;

   task body Worker is
   begin
      loop
         Count := Count + 1;                            --  EXPECT BHF-411
      end loop;
   end Worker;

   function Current return Natural is
   begin
      return Count;
   end Current;
end Vuln;
