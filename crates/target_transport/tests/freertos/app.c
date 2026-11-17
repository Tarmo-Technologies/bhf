/* SPDX-License-Identifier: Apache-2.0 */
#include <stdint.h>
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"

/* ---- BHF coverage ring (Ada memory_buffer format) + I/O contract ---- */
#define RING_CAP 512
volatile uint8_t  adafuzz_probe_memory_buffer[RING_CAP];
volatile uint32_t adafuzz_probe_memory_buffer_write = 0;
volatile uint8_t  adafuzz_probe_memory_buffer_wrapped = 0;
volatile uint32_t adafuzz_probe_memory_buffer_capacity = RING_CAP;
static void ring_write_byte(uint8_t v){
  adafuzz_probe_memory_buffer[adafuzz_probe_memory_buffer_write] = v;
  if (adafuzz_probe_memory_buffer_write == RING_CAP - 1){ adafuzz_probe_memory_buffer_write = 0; adafuzz_probe_memory_buffer_wrapped = 1; }
  else { adafuzz_probe_memory_buffer_write++; }
}
static void emit_crumb(uint32_t id){
  ring_write_byte(3);
  ring_write_byte((uint8_t)(id & 0xff)); ring_write_byte((uint8_t)((id>>8)&0xff));
  ring_write_byte((uint8_t)((id>>16)&0xff)); ring_write_byte((uint8_t)((id>>24)&0xff));
}
/* The host writes the fuzz input here AFTER loadvm (restore to the pre-startup
 * baseline) and BEFORE the continue runs Reset_Handler. A plain global would land
 * in .bss and be zeroed by startup's .bss-clear loop, erasing the injected input
 * before the producer reads it (#84). The .noinit section (see link.ld) is placed
 * after .bss and is NOLOAD, so neither the .bss zero loop nor the .data copy
 * touches it — the delivered input survives the reset-through-startup continue. */
volatile uint8_t  bhf_input[64] __attribute__((section(".noinit")));
volatile uint32_t bhf_fault_flag = 0;   /* #72 fault-status word (zero-init per run: no inherited fault) */
volatile uint32_t bhf_task_id    = 0;   /* #84 current-task identity observation */
/* State one input leaves for the next (#249). It is in .noinit, so startup
 * does not clear it: only the transport's snapshot reset does. If a reset ever
 * leaked it, the 0x42 after a 0xC5 would fault. */
volatile uint32_t bhf_carryover __attribute__((section(".noinit")));
/* The kernel's version string, kept in the image so `firmware=` can record
 * which kernel the target runs (#248). */
__attribute__((used)) const char bhf_kernel_version[] = "FreeRTOS Kernel " tskKERNEL_VERSION_NUMBER;

/* The host plants a gdb breakpoint at this symbol, so it must NOT be inlined
 * into its callers (otherwise the breakpoint address is never executed and the
 * run-control `continue` never stops). */
__attribute__((noinline, used)) void harness_done(void){ for(;;){} }

void HardFault_Handler(void){
  emit_crumb(0xFA17);
  bhf_fault_flag = 0xDEADFA11u;
  harness_done();
}

static QueueHandle_t q;

#ifdef BHF_ISR_ENTRY
/* The interrupt-driven entry point (#252): a receive interrupt hands the input
 * to the consumer through the queue, from ISR context, as a UART RX handler
 * hands a received byte to its task. QEMU ignores a debugger's writes to the
 * NVIC, so main() pends the interrupt itself to stand for the byte arriving. */
void IRQ0_Handler(void){
  BaseType_t woken = pdFALSE;
  uint8_t b = bhf_input[0];
  emit_crumb(0x15A0);                              /* ISR-entry marker */
  xQueueSendFromISR(q, &b, &woken);
  portYIELD_FROM_ISR(woken);
}
#define NVIC_ISER0 (*(volatile uint32_t *)0xE000E100u)
#define NVIC_ISPR0 (*(volatile uint32_t *)0xE000E200u)
#define NVIC_IPR0  (*(volatile uint8_t  *)0xE000E400u)
#endif

/* Producer task: forward the fuzz input one message to the consumer. */
static void producer(void *p){ (void)p;
  uint8_t b = bhf_input[0];
  xQueueSend(q, &b, 0);
  vTaskSuspend(NULL);
}
/* Consumer task: the SELECTED entry point. Records its task id, dispatches on
 * the message, emits coverage, and signals completion. */
static void consumer(void *p){ (void)p;
  uint8_t b;
  xQueueReceive(q, &b, portMAX_DELAY);
  bhf_task_id = (uint32_t)(uintptr_t)xTaskGetCurrentTaskHandle();
  emit_crumb(0x75C0);                              /* task-identity marker: consumer */
  emit_crumb(0x100); emit_crumb(0x101);           /* prologue edges */
  if (bhf_carryover == 0xC5u && b == 0x42){ emit_crumb(0x2C6); __asm volatile("udf #0"); }
  if (b == 0xF7){ emit_crumb(0x1FA); __asm volatile("udf #0"); emit_crumb(0x1FB); }
  else if (b == 0x42){ emit_crumb(0x200); emit_crumb(0x201); }
  /* A hang: never reaches harness_done, so the run ends at the deadline. */
  else if (b == 0xD0){ emit_crumb(0x2D0); for(;;){ __asm volatile("nop"); } }
  /* Busy work that grows with the input, for the cycle counter (#251). A
   * unit is long next to the run's delivery and completion, whose cost
   * varies from boot to boot by a few thousand counter ticks. */
  else if (b >= 0xB0 && b <= 0xBF){
    emit_crumb(0x2B0);
    for (volatile uint32_t i = 0; i < (uint32_t)(b - 0xAF) * 200000u; i++){}
  }
  /* Leaves state behind for the next input (see bhf_carryover). */
  else if (b == 0xC5){ emit_crumb(0x2C5); bhf_carryover = 0xC5u; }
  else { emit_crumb(0x300); }
  harness_done();
}

int main(void){
  q = xQueueCreate(4, sizeof(uint8_t));
  xTaskCreate(consumer, "consumer", configMINIMAL_STACK_SIZE, NULL, 2, NULL);
#ifdef BHF_ISR_ENTRY
  /* Below configMAX_SYSCALL_INTERRUPT_PRIORITY, so the handler may use the
   * FromISR API. The kernel masks it until the first task starts. */
  NVIC_IPR0 = 6 << (8 - configPRIO_BITS);
  NVIC_ISER0 = 1u;
  NVIC_ISPR0 = 1u;
#else
  xTaskCreate(producer, "producer", configMINIMAL_STACK_SIZE, NULL, 1, NULL);
#endif
  vTaskStartScheduler();
  for(;;){}
}
/* FreeRTOS hooks the port requires (minimal). */
void vApplicationMallocFailedHook(void){ harness_done(); }
void vApplicationStackOverflowHook(TaskHandle_t t, char *n){ (void)t;(void)n; harness_done(); }
