--  SPDX-License-Identifier: Apache-2.0
--  Campaign 2026-07-03 Ada regression guards. A `with`/`use` context clause is
--  an import, not a hazard site; `Selected`/`Selection` must not match the
--  `select` tasking keyword; a subprogram declaration is not a file-open call.
--  Lines without `EXPECT` must produce no finding.
with GNAT.OS_Lib;                     --  safe: import, not a spawn (BHF-412)
with Ada.Unchecked_Deallocation;      --  safe: import, not a free site (BHF-410)
with Ada.Unchecked_Conversion;        --  safe: import, not a conversion (BHF-409)
use GNAT.OS_Lib;                      --  safe: use clause

package body Fp_Guards is

   --  BHF-405: a subprogram DECLARATION is not a call site.
   function Open (Path : String) return File_Descriptor;

   procedure Run (User_Path : String; Cmd : String) is
      Selected : Integer := 0;        --  safe: not the `select` keyword (BHF-411)
      Selection_Count : Integer := 1; --  safe: not the `select` keyword
      FD : File_Descriptor;
      F  : Ada.Text_IO.File_Type;
   begin
      Selected := Selection_Count;
      GNAT.OS_Lib.Spawn (Cmd);        --  EXPECT BHF-304 (taint supersedes BHF-412)
      FD := FS.Open (Path => User_Path); --  safe: not a known file-open API
      Ada.Text_IO.Open (F, In_File, User_Path); --  EXPECT BHF-405
   end Run;

   --  BHF-412: a spawn of a local constant program is not a finding; a spawn of
   --  a program taken from a record component (not taint-modelled) is.
   procedure Launch (Cfg : Config) is
      Fixed : constant String := "/bin/ls";
   begin
      Trace.Detail ("Spawning: " & Fixed); --  safe: keyword only in a log string
      GNAT.OS_Lib.Spawn (Fixed, No_Args, Ok);        --  safe: constant program
      GNAT.OS_Lib.Spawn (Cfg.Tool.all, No_Args, Ok); --  EXPECT BHF-412
   end Launch;                        --  safe: `end` terminator, not a call

   function Unchecked_Spawn (Cmd : String) return Integer; --  safe: declaration

   --  BHF-410 / BHF-409: an instantiation alone is not a finding; a conversion
   --  that forges an access value is.
   procedure Free is new Ada.Unchecked_Deallocation (Object, Object_Access); --  safe
   function Conv is new Ada.Unchecked_Conversion (Source, Target);           --  safe
   function To_Obj is new Ada.Unchecked_Conversion (System.Address, Object_Access); --  EXPECT BHF-409

end Fp_Guards;
