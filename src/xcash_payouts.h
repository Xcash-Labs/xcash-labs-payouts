#ifndef XCASH_PAYOUTS_H_   /* Include guard */
#define XCASH_PAYOUTS_H_

#include <argp.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include "config.h"
#include "macro_functions.h"
#include "globals.h"
#include "db_init.h"
#include "structures.h"
#include "xcash_payouts_loop.h"
#include "net_server.h"
#include "init_processing.h"

// Define an enum for option IDs
typedef enum {
    OPTION_LOG_LEVEL
} option_ids;

#endif