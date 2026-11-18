# SPDX-License-Identifier: Apache-2.0
# The bhf reference agent on Zephyr (#291): build with
#   west build -b qemu_cortex_m3 c_runtime/zephyr/samples/agent
# and drive it with `bhf fuzz --target-transport agent:tcp:...` over the
# board's second UART (see c_runtime/zephyr/README.md).
cmake_minimum_required(VERSION 3.20.0)
list(APPEND ZEPHYR_EXTRA_MODULES ${CMAKE_CURRENT_SOURCE_DIR}/../..)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(bhf_agent_sample)

target_sources(app PRIVATE src/main.c src/target.c)
# Only the code under test is instrumented: the agent and Zephyr are not.
set_source_files_properties(src/target.c PROPERTIES COMPILE_OPTIONS -fsanitize-coverage=trace-pc)
