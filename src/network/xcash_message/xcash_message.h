#ifndef XCASH_MESSAGE_H
#define XCASH_MESSAGE_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cjson/cJSON.h>
#include "config.h"
#include "globals.h"
#include "macro_functions.h"
#include "structures.h"
#include "net_server.h"
#include "server_functions.h"
#include "network_security_functions.h"
#include "delegate_server_functions.h"

void handle_srv_message(const char *data, size_t length, server_client_t* client);

#endif  // XCASH_MESSAGE_H