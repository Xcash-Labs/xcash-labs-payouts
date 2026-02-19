#include "xcash_payouts.h"

static volatile sig_atomic_t sig_requests = 0;
static char doc[] =
"\n"
BRIGHT_WHITE_TEXT("General Options:\n")
"Program Bug Address: https://github.com/Xcash-Labs/xcash-labs-dpops/issues\n"
"\n"
"  -h, --help                              List all valid parameters.\n"
"\n"
BRIGHT_WHITE_TEXT("Debug Options:\n")
"  --log-level                             The log-level displays log messages based on the level passed:\n"
"                                          Critial - 0, Error - 1, Warning - 2, Info - 3, Debug - 4\n"
"\n"
"For more details on each option, refer to the documentation or use the --help option.\n";

static struct argp_option options[] = {
  {"help", 'h', 0, 0, "List all valid parameters.", 0},
  {"log-level", OPTION_LOG_LEVEL, "LOG_LEVEL", 0, "Displays log messages based on the level passed.", 0},
  {0}
};

/*---------------------------------------------------------------------------------------------------------
Name: error_t parse_opt
Description: Load program options.  Using the argp system calls.
---------------------------------------------------------------------------------------------------------*/
static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
  arg_config_t *cfg = (arg_config_t *)state->input;

  switch (key)
  {
    case 'h':
      cfg->show_help = true;
      break;

    case OPTION_LOG_LEVEL: {
      if (atoi(arg) >= 0 && atoi(arg) <= 4)
      {
        log_level = atoi(arg);
      }
      break;
      }
    default:
      return ARGP_ERR_UNKNOWN;
  }

  return 0;
}


static struct argp argp = {options, parse_opt, 0, doc, NULL, NULL, NULL};

/*---------------------------------------------------------------------------------------------------------
Name: cleanup_data_structure
Description: Clean up before ending
---------------------------------------------------------------------------------------------------------*/
void cleanup_data_structures(void) {

  // Free heap buffers allocated in init_globals().
  if (server_limit_IP_address_list) {
    free(server_limit_IP_address_list);
    server_limit_IP_address_list = NULL;
  }
  if (server_limit_public_address_list) {
    free(server_limit_public_address_list);
    server_limit_public_address_list = NULL;
  }

  // Wipe sensitive material (best-effort).
  memset(xcash_wallet_public_address, 0, sizeof(xcash_wallet_public_address));
  pthread_mutex_destroy(&database_data_IP_address_lock);

  return;
}

/*---------------------------------------------------------------------------------------------------------
Name: sigint_handler
Description: Shuts program down on signal
---------------------------------------------------------------------------------------------------------*/
void sigint_handler(int sig_num) {
 (void)sig_num;
  sig_requests++;
  if (sig_requests == 1) {
    static const char msg[] = "\nShutdown request received. Finishing current transaction, please wait...\n";
    if (write(STDERR_FILENO, msg, sizeof(msg) - 1) < 0) { /* ignore */ }
  }
  atomic_store(&shutdown_requested, true);
  if (sig_requests >= 2) {
    _exit(0);
  }
}

void install_signal_handlers(void) {
  struct sigaction sa = {0};
  sa.sa_handler = sigint_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART;
  sigaction(SIGINT,  &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);
}

/*---------------------------------------------------------------------------------------------------------
Name: is_ntp_enabled
Description: Checks if ntp is enabled for the server
---------------------------------------------------------------------------------------------------------*/
bool is_ntp_enabled(void) {
  FILE *fp;
  char buffer[256];
  bool ntp_active = false;

  fp = popen("timedatectl status", "r");
  if (fp == NULL) {
      perror("popen failed");
      return false;
  }

  while (fgets(buffer, sizeof(buffer), fp)) {
      if (strstr(buffer, "System clock synchronized: yes") ||
          strstr(buffer, "NTP service: active")) {
          ntp_active = true;
          break;
      }
  }

  pclose(fp);
  return ntp_active;
}

void fix_pipe(int fd) {
  if (fcntl(fd, F_GETFD) != -1 || errno != EBADF) {
    return;
  }

  int f = open("/dev/null", fd == STDIN_FILENO ? O_RDONLY : O_WRONLY);
  if (f == -1) {
    FATAL_ERROR_EXIT("failed to open /dev/null for missing stdio pipe");
    // abort();
  }
  if (f != fd) {
    dup2(f, fd);
    close(f);
  }
}

/*---------------------------------------------------------------------------------------------------------
Name: main
Description: The start point of the program
Parameters:
  parameters_count - The parameter count
  parameters - The parameters
Return: 0 if an error has occured, 1 if successfull
---------------------------------------------------------------------------------------------------------*/
int main(int argc, char *argv[]) {
  arg_config_t arg_config = {0};
  arg_config.show_help = false;
  init_globals();
  install_signal_handlers();
  setenv("ARGP_HELP_FMT", "rmargin=120", 1);

  if (argp_parse(&argp, argc, argv, ARGP_NO_EXIT | ARGP_NO_ERRS, 0, &arg_config) != 0) {
    FATAL_ERROR_EXIT("Invalid option entered. Try `xcash-dpops --help'");
  }
  if (arg_config.show_help) {
    argp_help(&argp, stdout, ARGP_NO_HELP, argv[0]);
    return 0;
  }

  if (is_ntp_enabled()) {
    INFO_PRINT("NTP Service is Active");
  } else {
    FATAL_ERROR_EXIT("Please enable ntp for your server");
  }

  if (!get_node_data()) {
    FATAL_ERROR_EXIT("Can't get node data");
  }

  if (xcash_wallet_public_address[0] == '\0' || strlen(xcash_wallet_public_address) != XCASH_WALLET_LENGTH) {
    FATAL_ERROR_EXIT("The --wallet-address and should be %d characters long!", XCASH_WALLET_LENGTH);
  }

  if (!start_tcp_server(XCASH_PAYOUTS_PORT)) {
    FATAL_ERROR_EXIT("Failed to start TCP server");
  }

  if (!initialize_database()) {
    stop_tcp_server();
    FATAL_ERROR_EXIT("Can't open mongo database");
  }

  g_ctx = dnssec_init();

  if (print_starter_state(&arg_config)) {
    start_payouts_process();
  }
  
  atomic_store(&shutdown_requested, true);
  fprintf(stderr, "Daemon is shutting down...\n");

  if (g_ctx) {
    dnssec_destroy(g_ctx);
    g_ctx = NULL;
  }

  shutdown_db();
  INFO_PRINT("Database shutdown successfully");
  stop_tcp_server();
  cleanup_data_structures();
  return 0;
}