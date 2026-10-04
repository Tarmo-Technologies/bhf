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
  if (b == 0xF7){ emit_crumb(0x1FA); __asm volatile("udf #0"); emit_crumb(0x1FB); }
  else if (b == 0x42){ emit_crumb(0x200); emit_crumb(0x201); }
  else { emit_crumb(0x300); }
  harness_done();
}

int main(void){
  q = xQueueCreate(4, sizeof(uint8_t));
  xTaskCreate(consumer, "consumer", configMINIMAL_STACK_SIZE, NULL, 2, NULL);
  xTaskCreate(producer, "producer", configMINIMAL_STACK_SIZE, NULL, 1, NULL);
  vTaskStartScheduler();
  for(;;){}
}
/* FreeRTOS hooks the port requires (minimal). */
void vApplicationMallocFailedHook(void){ harness_done(); }
void vApplicationStackOverflowHook(TaskHandle_t t, char *n){ (void)t;(void)n; harness_done(); }
