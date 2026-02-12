#ifndef GLOBALS_H_   /* Include guard */
#define GLOBALS_H_


#include <mongoc/mongoc.h>
#include <stdatomic.h>
#include "config.h"
#include "macro_functions.h"
#include "structures.h"

/*--------------------------------------------------------------------------------------------------
Global Variables
--------------------------------------------------------------------------------------------------*/
extern mongoc_client_pool_t* database_client_thread_pool;  // database
extern int log_level;
extern atomic_bool shutdown_requested;
extern dnssec_ctx_t* g_ctx;
extern char xcash_wallet_public_address[XCASH_WALLET_LENGTH + 1];
extern NetworkNode network_nodes[];
extern const char* endpoints[];
extern char self_sha[SHA256_DIGEST_SIZE + 1];
extern char* server_limit_IP_address_list; // holds all of the IP addresses that are currently running on the server.
extern char* server_limit_public_address_list; // holds all of the public addresses that are currently running on the server.
extern const char* xcash_net_messages[];
extern int network_data_nodes_amount;
extern NetworkNode network_nodes[];

void init_globals(void);

#endif