#include "db_init.h"

bool initialize_database(void) {
  char mongo_uri[512];  // Increased buffer size for full URI
  configure_mongo_error_only_logging();
  strncpy(mongo_uri, DATABASE_CONNECTION, sizeof(mongo_uri) - 1);
  mongo_uri[sizeof(mongo_uri) - 1] = '\0';
  if (!initialize_mongo_database(mongo_uri, &database_client_thread_pool)) {
    return false;
  }

  return true;
}

static void error_only_log_handler(mongoc_log_level_t log_level_mongo,
                                   const char *log_domain,
                                   const char *message,
                                   void *user_data) {
  (void)user_data;
  // The can be changed base on MongoDB Log Levels, Only displaying errors for now
  if (log_level_mongo == MONGOC_LOG_LEVEL_ERROR) {
    ERROR_PRINT("[MONGODB ERROR] %s: %s", log_domain, message);
  }
}

void configure_mongo_error_only_logging(void) {
    mongoc_log_set_handler(error_only_log_handler, NULL);
}

void shutdown_db(void){
    shutdown_mongo_database(&database_client_thread_pool);
}

bool initialize_mongo_database(const char *mongo_uri, mongoc_client_pool_t **db_client_thread_pool) {
    mongoc_uri_t *uri_thread_pool;
    bson_error_t error;
    // Initialize the MongoDB client library
    mongoc_init();
    // Create a new URI object from the provided URI string
    uri_thread_pool = mongoc_uri_new_with_error(mongo_uri, &error);
    if (!uri_thread_pool) {
        ERROR_PRINT("Failed to parse URI: %s\nError message: %s", mongo_uri, error.message);
        return XCASH_ERROR;
    }
    // Create a new client pool with the parsed URI object
    *db_client_thread_pool = mongoc_client_pool_new(uri_thread_pool);
    if (!*db_client_thread_pool) {
        ERROR_PRINT("Failed to create a new client pool.");
        mongoc_uri_destroy(uri_thread_pool);
        return XCASH_ERROR;
    }
    mongoc_uri_destroy(uri_thread_pool);
    return XCASH_OK;
}

void shutdown_mongo_database(mongoc_client_pool_t **db_client_thread_pool) {
    if (*db_client_thread_pool) {
        mongoc_client_pool_destroy(*db_client_thread_pool);
        *db_client_thread_pool = NULL;
    }
    mongoc_cleanup();
}