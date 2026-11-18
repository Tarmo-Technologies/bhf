/* SPDX-License-Identifier: Apache-2.0 */
/*
 * bhf reference agent on Zephyr (#291).
 */
#ifndef BHF_AGENT_ZEPHYR_H
#define BHF_AGENT_ZEPHYR_H

#include "bhf_agent.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Serve the agent protocol on the UART the devicetree's chosen
 * `bhf,agent-uart` names, running `entry` for each input, in an agent
 * thread. A fatal error in the code under test (a CPU exception, a failed
 * assertion) ends that thread: this thread reports the fault for the input
 * and starts a new agent thread for the next one. Does not return. */
void bhf_agent_zephyr_run(bhf_agent_entry_fn entry);

#ifdef __cplusplus
}
#endif

#endif /* BHF_AGENT_ZEPHYR_H */
