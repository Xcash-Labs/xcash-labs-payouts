#include "init_processing.h"

/*---------------------------------------------------------------------------------------------------------
Name: print_starter_state
Description: Print program start header.
---------------------------------------------------------------------------------------------------------*/
bool print_starter_state(const arg_config_t *arg_config) {
  (void) arg_config;
  size_t i = 0;
  int count_seeds = 0;
  static const char xcash_tech_header[] =
      "\n"
      " /$$   /$$                           /$$        / $$              / $$                    \n"
      "| $$  / $$                          | $$        | $$              | $$                    \n"
      "|  $$/ $$/ /$$$$$$$ /$$$$$$  /$$$$$$| $$$$$$$   | $$      /$$$$$$ | $$       /$$$$$$      \n"
      " \\  $$$$/ /$$_____/|____  $$/$$_____| $$__  $$  | $$     |____  $$| $$      /$$_____     \n"
      "  /$$  $$| $$       /$$$$$$|  $$$$$$| $$  \\ $$  | $$      /$$$$$$ | $$$$$$$ | $$$$$$     \n"
      " /$$/\\  $| $$      /$$__  $$\\____  $| $$  | $$  | $$     /$$__  $$| $$   $$ \\____  $$  \n"
      "| $$  \\ $|  $$$$$$|  $$$$$$$/$$$$$$$| $$  | $$/ | $$$$$$$| $$$$$$$| $$$$$$$ |$$$$$$$     \n"
      "|__/  |__/\\_______/\\_______|_______/|__/  |__|__|________/\\_______/\\________/\\______/\n"
      "\n";
  fputs(xcash_tech_header, stderr);
  time_t now = time(NULL);
  char time_str[64];
  strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));
  fprintf(stderr,
          "%s (%s)\n\n"
          "Wallet Public Address:\t%s\n"
          "\n"
          "Services:\n"
          "Daemon:\t\t%s:%d\n"
          "DPoPS:\t\t%s:%d\n"
          "Wallet:\t\t%s:%d\n"
          "Payouts:\t%s:%d\n"
          "MongoDB:\t%s\n"
          "Log level:\t%d\n"
          "Image Hash:\t%s\n",
          XCASH_PAYOUTS_CURRENT_VERSION, "~Lazarus",
          xcash_wallet_public_address,
          XCASH_DAEMON_IP, XCASH_DAEMON_PORT,
          XCASH_DPOPS_IP, XCASH_DPOPS_PORT,
          XCASH_WALLET_IP, XCASH_WALLET_PORT,
          XCASH_PAYOUTS_IP, XCASH_PAYOUTS_PORT,
          DATABASE_CONNECTION, log_level, self_sha);

//
// Checking DNSSEC records for seeds and image version using xcashpulse dns entries
//
  INFO_PRINT("Validating DNSSEC entries...");
  for (i = 0; network_nodes[i].ip_address != NULL; i++) {
    bool have = false;
    dnssec_status_t st = dnssec_query(g_ctx, network_nodes[i].ip_address, RR_IN, &have);
    if (st == DNSSEC_SECURE && have) {
      count_seeds++;
    }
  }

  if (!(count_seeds == network_data_nodes_amount)) {
    ERROR_PRINT("Could not validate DNSSEC records for seed nodes, unable to start");
    return false;
  }

  fprintf(stderr, "[%s] Daemon startup successful and is busy processing requests...\n\n", time_str);
  return true;
}