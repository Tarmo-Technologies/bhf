# SPDX-License-Identifier: Apache-2.0
# The bhf reference agent as a Zephyr module (#291): add this directory to
# ZEPHYR_EXTRA_MODULES and set CONFIG_BHF_AGENT=y.
if(CONFIG_BHF_AGENT)
  zephyr_library()
  zephyr_include_directories(${CMAKE_CURRENT_LIST_DIR} ${CMAKE_CURRENT_LIST_DIR}/..)
  zephyr_library_sources(${CMAKE_CURRENT_LIST_DIR}/../bhf_agent.c bhf_agent_zephyr.c)
  # Zephyr ends a thread that faults: the agent records the fault, and the
  # thread that started it replies (bhf_agent_report_fault).
  zephyr_library_compile_definitions(BHF_AGENT_NO_SETJMP)
endif()
