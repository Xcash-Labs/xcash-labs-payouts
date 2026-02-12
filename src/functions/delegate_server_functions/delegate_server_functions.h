#ifndef DELEGATE_SERVER_FUNCTIONS_H_
#define DELEGATE_SERVER_FUNCTIONS_H_

#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include "VRF_functions.h"
#include "config.h"
#include "globals.h"
#include "macro_functions.h"
#include "db_functions.h"
#include "xcash_delegates.h"
#include "net_server.h"
#include "string_functions.h"
#include "xcash_round.h"
#include "network_daemon_functions.h"
#include "network_wallet_functions.h"

void server_receive_payout(const char *MESSAGE);

#endif