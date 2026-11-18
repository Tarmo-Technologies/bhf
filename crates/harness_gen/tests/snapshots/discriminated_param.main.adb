--  generated_harnesses/H-0042/main.adb
--  SPDX-License-Identifier: Apache-2.0
pragma Ada_2012;
with Ada.Streams; use Ada.Streams;
with Ada.Exceptions;
with Interfaces; use Interfaces;
with AdaFuzz.Input;
with AdaFuzz.Decode;
with AdaFuzz.Probe;
with Switch;

procedure Main is
   use type Interfaces.Unsigned_64;

   Buf  : aliased Stream_Element_Array := (1 .. 1 * 1024 * 1024 => 0);
   Last : Stream_Element_Offset;
   TC   : AdaFuzz.Probe.Testcase_Id := 0;
begin
   loop
      AdaFuzz.Input.Load_From_Stdin (Buf, Last);
      exit when Last < Buf'First;
      TC := TC + 1;
      AdaFuzz.Probe.Begin_Testcase (TC);
      AdaFuzz.Probe.Set_Target (16#000D#);
      begin
      declare
         Cur : AdaFuzz.Decode.Cursor := AdaFuzz.Decode.Open (Buf'Unchecked_Access, Last);
         function Decode_R return Variant_Record is
         begin
            case Natural (AdaFuzz.Decode.Bounded_Range (Cur, 0, 4)) is
               when 0 => return Variant_Record'(Kind => Integer (0), others => <>);
               when 1 => return Variant_Record'(Kind => Integer (1), others => <>);
               when 2 => return Variant_Record'(Kind => Integer (2), others => <>);
               when 3 => return Variant_Record'(Kind => Integer (3), others => <>);
               when others => return Variant_Record'(Kind => Integer (4), others => <>);
            end case;
         end Decode_R;
         R : Variant_Record := Decode_R;
      begin
         AdaFuzz.Probe.Target_Entry;
         Switch (R);
      exception
         when AdaFuzz_E : others =>
            AdaFuzz.Probe.On_Top_Level_Catch
              (Ada.Exceptions.Exception_Name (AdaFuzz_E),
               Ada.Exceptions.Exception_Message (AdaFuzz_E));
      end;
      exception
         when others =>
            --  A parameter initializer raised in the declarative part (e.g. a
            --  decoder draw outside the parameter's subtype range), which the
            --  inner handler above cannot catch. Skip this input rather than
            --  let the exception escape and crash the harness process.
            null;
      end;
      AdaFuzz.Probe.End_Testcase;
      AdaFuzz.Probe.Flush;
   end loop;
end Main;
