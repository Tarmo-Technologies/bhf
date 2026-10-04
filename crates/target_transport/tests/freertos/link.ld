/* SPDX-License-Identifier: Apache-2.0 */
MEMORY { FLASH (rx) : ORIGIN = 0x00000000, LENGTH = 4M
         RAM   (rwx): ORIGIN = 0x20000000, LENGTH = 4M }
ENTRY(Reset_Handler)
SECTIONS {
  .text : { KEEP(*(.isr_vector)) *(.text*) *(.rodata*) } > FLASH
  _sidata = LOADADDR(.data);
  .data : { _sdata = .; *(.data*) . = ALIGN(4); _edata = .; } > RAM AT > FLASH
  .bss  : { _sbss = .; *(.bss*) *(COMMON) . = ALIGN(4); _ebss = .; } > RAM
  /* .noinit holds the host-injected input staging buffer (bhf_input). It sits
     AFTER .bss so the startup _sbss.._ebss zero loop does NOT clear it, and is
     NOLOAD so the .data copy never overwrites it: the input the host writes
     after loadvm survives the reset-through-startup continue (#84). */
  .noinit (NOLOAD) : { . = ALIGN(4); _snoinit = .; *(.noinit*) . = ALIGN(4); _enoinit = .; } > RAM
  . = ALIGN(8); _end = .;
  . = ORIGIN(RAM) + LENGTH(RAM); _estack = .;
}
