#ifndef NETWORK_SECURITY_FUNCTIONS_H_   /* Include guard */
#define NETWORK_SECURITY_FUNCTIONS_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <mongoc/mongoc.h>
#include <bson/bson.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h> 
#include <unbound.h>
#include <math.h>
#include "config.h"
#include "macro_functions.h"
#include "globals.h"
#include "db_functions.h"
#include "network_daemon_functions.h"
#include "network_functions.h"
#include "string_functions.h"

bool is_seed_address(const char* public_address);
int verify_the_ip(const char *message, const char *client_ip, bool seed_only);
bool sign_txt_string(const char* txt_string, char* signature_out, size_t sig_out_len);
int wallet_verify_signature(const char *sign_str, const char *in_public_address, const char *in_signature);
dnssec_ctx_t* dnssec_init(void);
void dnssec_destroy(dnssec_ctx_t* h);
dnssec_status_t dnssec_query(dnssec_ctx_t* h, const char* name, int rrtype, bool* out_havedata);
bool validate_server_IP(void);

#endif