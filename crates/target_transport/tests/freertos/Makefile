# SPDX-License-Identifier: Apache-2.0
#
# The reference target-side agent as a FreeRTOS task on mps2-an385 (#290):
#
#   make agent.elf KERNEL=/path/to/FreeRTOS-Kernel   # at the pinned commit
#   qemu-system-arm -M mps2-an385 -nographic -monitor none \
#       -serial tcp:127.0.0.1:5555,server=on,wait=off -kernel agent.elf &
#   bhf fuzz bhf_work --harness H-rtos-agent \
#       --target-transport agent:tcp:127.0.0.1:5555 --max-len 256
#
# The agent and the kernel are built without coverage; the code under test
# (agent_target.c) with GCC's trace-pc, whose edges the agent reports.
KERNEL ?= FreeRTOS-Kernel
CC := arm-none-eabi-gcc
CFLAGS := -mcpu=cortex-m3 -mthumb -ffreestanding -O1 -g
RUNTIME := ../../../../c_runtime
PORT := $(KERNEL)/portable/GCC/ARM_CM3
INCLUDES := -I. -I$(RUNTIME) -I$(KERNEL)/include -I$(PORT)

agent.elf: agent_target.o agent_task.c startup.c link.ld $(RUNTIME)/bhf_agent.c
	$(CC) $(CFLAGS) -nostdlib -nostartfiles $(INCLUDES) -T link.ld -o $@ \
	  startup.c agent_task.c $(RUNTIME)/bhf_agent.c agent_target.o \
	  $(KERNEL)/tasks.c $(KERNEL)/queue.c $(KERNEL)/list.c $(PORT)/port.c \
	  $(KERNEL)/portable/MemMang/heap_4.c -lgcc

agent_target.o: agent_target.c
	$(CC) $(CFLAGS) -fsanitize-coverage=trace-pc -c $< -o $@

clean:
	rm -f agent.elf agent_target.o

.PHONY: clean
