--  SPDX-License-Identifier: Apache-2.0
--  The probe under a name an Ada 83 unit can `with` (#284). Ada 83 has no
--  child units, so a unit built under `pragma Ada_83` or `-gnat83` cannot
--  name AdaFuzz.Probe: the instrumenter's calls in such a unit go through
--  this library-level package instead.
pragma Ada_95;
with AdaFuzz.Probe;

package AdaFuzz_Probe83 is

   pragma Preelaborate;

   procedure Breadcrumb (Id : AdaFuzz.Probe.Crumb_Id)
     renames AdaFuzz.Probe.Breadcrumb;

   function Last_Breadcrumb return AdaFuzz.Probe.Crumb_Id
     renames AdaFuzz.Probe.Last_Breadcrumb;

   procedure On_Explicit_Raise
     (Exception_Name : String;
      File           : String;
      Line           : Natural;
      Breadcrumb     : AdaFuzz.Probe.Crumb_Id)
     renames AdaFuzz.Probe.On_Explicit_Raise;

end AdaFuzz_Probe83;
