/* SPDX-License-Identifier: Apache-2.0 */
MEMORY { FLASH (rx) : ORIGIN = 0x00000000, LENGTH = 4M
         RAM   (rwx): ORIGIN = 0x20000000, LENGTH = 4M }
ENTRY(Reset_Handler)
SECTIONS {
  .text : { KEEP(*(.isr_vector)) *(.text*) *(.rodata*) } > FLASH
  _sidata = LOADADDR(.data);
  .data : { _sdata = .; *(.data*) . = ALIGN(4); _edata = .; } > RAM AT > FLASH
  .bss  : { _sbss = .; *(.bss*) *(COMMON) . = ALIGN(4); _ebss = .; } > RAM
  . = ALIGN(8); _end = .;
  . = ORIGIN(RAM) + LENGTH(RAM); _estack = .;
}
