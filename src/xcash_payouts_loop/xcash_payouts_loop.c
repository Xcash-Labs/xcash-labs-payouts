#include "xcash_payouts_loop.h"

/*---------------------------------------------------------------------------------------------------------
Name: start_payouts_process
Description:
  Main loop for the payouts_process..

  - Waits until the local node is fully synchronized with the blockchain before starting.
  - Every BLOCK_TIME window, attempts to create a new round and produce a block.
  - If within the PoS bootstrap phase, only the designated seed node can initiate the round.
  - Handles retry logic, round failures, and optional database reinitialization if needed.
  - Uses the current block height and timing intervals to align with the DPoPS round schedule.

  This function is designed to be run continuously as part of the main production thread.

Parameters:
  None

Returns:
  None
---------------------------------------------------------------------------------------------------------*/
void start_payouts_process(void) {
  INFO_PRINT("xcash-payouts starting");

  while (!atomic_load(&shutdown_requested)) {
    sleep(60);
  }

}