/* SPDX-License-Identifier: Apache-2.0 */
#include <stdint.h>
extern uint32_t _estack, _sidata, _sdata, _edata, _sbss, _ebss;
int main(void);
void Reset_Handler(void);
void Default_Handler(void){ for(;;){} }
/* Provided elsewhere: app.c (HardFault) and the FreeRTOS CM3 port (SVC/PendSV/SysTick). */
void HardFault_Handler(void);
void SVC_Handler(void);
void PendSV_Handler(void);
void SysTick_Handler(void);
void NMI_Handler(void)        __attribute__((weak, alias("Default_Handler")));
void MemManage_Handler(void)  __attribute__((weak, alias("Default_Handler")));
void BusFault_Handler(void)   __attribute__((weak, alias("Default_Handler")));
void UsageFault_Handler(void) __attribute__((weak, alias("Default_Handler")));
void DebugMon_Handler(void)   __attribute__((weak, alias("Default_Handler")));

__attribute__((section(".isr_vector"), used))
void (* const vectors[])(void) = {
  (void(*)(void))&_estack, Reset_Handler, NMI_Handler, HardFault_Handler,
  MemManage_Handler, BusFault_Handler, UsageFault_Handler, 0, 0, 0, 0,
  SVC_Handler, DebugMon_Handler, 0, PendSV_Handler, SysTick_Handler,
};

void Reset_Handler(void){
  uint32_t *src = &_sidata, *dst = &_sdata;
  while (dst < &_edata) *dst++ = *src++;      /* .data init */
  for (dst = &_sbss; dst < &_ebss; ) *dst++ = 0; /* .bss zero */
  main();
  for(;;){}
}
/* Minimal freestanding libc the kernel needs (no newlib). */
void *memcpy(void *d, const void *s, unsigned long n){ unsigned char *a=d; const unsigned char *b=s; while(n--) *a++=*b++; return d; }
void *memset(void *d, int c, unsigned long n){ unsigned char *a=d; while(n--) *a++=(unsigned char)c; return d; }
void *memmove(void *d, const void *s, unsigned long n){ unsigned char *a=d; const unsigned char *b=s; if(a<b){ while(n--) *a++=*b++; } else { a+=n; b+=n; while(n--) *--a=*--b; } return d; }
