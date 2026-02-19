#include "node_functions.h"

bool get_node_data(void) {
  // --- Wait for wallet public address to be available (from wallet process) ---
  const int SLEEP_SEC = 5;
  sleep(20);  // give things a chance to start-up
  int attempt = 0;

  for (;;) {
    if (get_public_address() && xcash_wallet_public_address[0] != '\0') {
      INFO_PRINT("Wallet is ready after %d attempt(s).", attempt);
      break;
    }
    ++attempt;
    WARNING_PRINT("Wallet not ready yet (attempt %d). Retrying in %ds...", attempt, SLEEP_SEC);
    sleep(SLEEP_SEC);
  }

  if (xcash_wallet_public_address[0] == '\0') {
    ERROR_PRINT("Wallet public address is empty");
    return false;
  }
  
  return true;
}