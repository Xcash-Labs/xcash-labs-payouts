#include "globals.h"

// set globals defined in globals.h

mongoc_client_pool_t* database_client_thread_pool = NULL;
char xcash_wallet_public_address[XCASH_WALLET_LENGTH + 1] = {0};
int log_level = 3;  // default level is error + warning + info - change back to 2 once system stabilizes
dnssec_ctx_t* g_ctx = NULL;
pthread_t server_thread;
atomic_bool shutdown_requested = ATOMIC_VAR_INIT(false);
atomic_bool payment_inprocess = ATOMIC_VAR_INIT(false);
int network_data_nodes_amount = 4;
NetworkNode network_nodes[] = {
  {"XCK1gUSXCuV4KANQz78YYFQuxeGzPwUtzToqnNGXwjFgjULzWQiYbdC9iJRPiLDqn1ijo9HpfXsDzSRjgKZAwK7x2fTAQZBLXF", "seeds.xcashseeds.us",
    "5b4a41a7018baf13484a1ecee2c8d166d9dca7ea5e570df9303a58f7d544ee15",0},
  {"XCK1XWPrVwB8zNxzViSfsxFEq4iCTE12wY8TRxnokob3jDijdzbq4gF1aJc45BDg62Rv6MWVzjxmrDVSFbTiJruQ5iNuA2p2K5", "seeds.xcashseeds.uk",
    "059f518b7ebad0888df0be80acff6b9a158f576673b31cb1aba3da76d4a8efda",0},
  {"XCK1WFfopbw4FRA4wUYvYxLVuu6WUK2WkVZJXMBuBYRaHhyo1JndU6CaWAjVsvQom4SCxf2FX7ZcrTTaejXPG8a59WGKH3nF7j", "seeds.xcashseeds.cc",
    "b7ad2355eda2037a3376049a2261d1941b78f1be6e305df60ba5fbdd783828dd",0},
  {"XCK1UBmZPkSDGApfrxPHxJMEusky2QPVfAFQ3DqxqXWCD4npsELyKZGQMebxUCJxcjN3pvckR7hddGm3p1HBV6wa3u6yAhiJx3", "seeds.xcashseeds.me",
    "63e71eb7c7152b4f27435925a489849680daf067e13631de647249d186062416",0},
  // Sentinel value (empty entry to mark the end)
  {NULL, NULL, NULL, 0}};
char* server_limit_IP_address_list;
char* server_limit_public_address_list;
const char* xcash_net_messages[] = {
  "SEED_TO_NODES_PAYOUT"};

// initialize the global variables
void init_globals(void) {
  server_limit_IP_address_list = (char*)calloc(15728640,sizeof(char)); // 15 MB
  server_limit_public_address_list = (char*)calloc(15728640,sizeof(char)); // 15 MB
   
  // check if the memory needed was allocated on the heap successfully
  if (server_limit_IP_address_list == NULL || server_limit_public_address_list == NULL)
  {
    FATAL_ERROR_EXIT("Can't allocate memory");
  }

  return;
}