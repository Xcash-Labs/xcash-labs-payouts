#include "xcash_message.h"

xcash_msg_t get_message_type(const char* data) {
  if (!data || *data == '\0') {
    return XMSG_NONE;  // Handle NULL or empty data safely
  }
  for (int i = 0; i < XMSG_MESSAGES_COUNT; i++) {
    if (strncmp(data, xcash_net_messages[i], strlen(xcash_net_messages[i])) == 0) {
      return (xcash_msg_t)i;
    }
  }
  return XMSG_NONE;  // Default case if no match is found
}

//
//  Handle Server Message
//
void handle_srv_message(const char* data, size_t length, server_client_t* client) {
  if (data == NULL || length == 0) {
    ERROR_PRINT("Message received by server is null.");
    return;
  }

  if (!client) {
    ERROR_PRINT("handle_srv_message: Client data is NULL");
    return;
  }

  DEBUG_PRINT("Processing message from client IP: %s", client->client_ip);

  char trans_type[128] = {0};
  if (strstr(data, "{") && strstr(data, "}")) {
    cJSON* json_obj = cJSON_Parse(data);
    if (!json_obj) {
      ERROR_PRINT("Invalid message received, JSON parsing error in handle_srv_message: %s", cJSON_GetErrorPtr());
      DEBUG_PRINT("Client IP: %s Message: %s", client->client_ip, data);
      return;
    }

    cJSON* settings_obj = cJSON_GetObjectItemCaseSensitive(json_obj, "message_settings");
    if (!cJSON_IsString(settings_obj) || (settings_obj->valuestring == NULL)) {
      ERROR_PRINT("Invalid message received, missing or invalid message_settings");
      cJSON_Delete(json_obj);
      return;
    }

    snprintf(trans_type, sizeof(trans_type), "%s", settings_obj->valuestring);
    cJSON_Delete(json_obj);

  } else {
    ERROR_PRINT("Message does not match expected JSON format");
    return;
  }
 
  xcash_msg_t msg_type = get_message_type(trans_type);

  // Must come from seed
  if (msg_type == XMSG_SEED_TO_NODES_UPDATE_VOTE_COUNT || msg_type == XMSG_SEED_TO_NODES_PAYOUT) {
    if (verify_the_ip(data, client->client_ip, true) != XCASH_OK) {
      ERROR_PRINT("IP seed check failed for msg_type=%s from %s", trans_type, client->client_ip);
      return;
    }
  }

  // Check if message is signed
  if (msg_type == XMSG_SEED_TO_NODES_UPDATE_VOTE_COUNT) {
    if (verify_data(data, msg_type) == XCASH_ERROR) {
      return;
    }
  }

  switch (msg_type) {

    case XMSG_SEED_TO_NODES_UPDATE_VOTE_COUNT:
      if (server_limit_IP_addresses(LIMIT_CHECK, client->client_ip) == 1) {
        server_receive_update_delegate_vote_count(data);
        server_limit_IP_addresses(LIMIT_REMOVE, client->client_ip);
      }
      break;

    case XMSG_SEED_TO_NODES_PAYOUT: {
      // Should always be false but just in case
      bool expected = false;
      if (!atomic_compare_exchange_strong_explicit(
              &payment_inprocess, &expected, true,
              memory_order_acq_rel,
              memory_order_relaxed))
      {
        ERROR_PRINT("Skipping payment processing, transaction currently in process");
        break;
      }

      if (server_limit_IP_addresses(LIMIT_CHECK, client->client_ip) == 1) {
        server_receive_payout(data); 
        server_limit_IP_addresses(LIMIT_REMOVE, client->client_ip);
      }

      // release the lock
      atomic_store_explicit(&payment_inprocess, false, memory_order_release);
      break;
    }

    default:
      ERROR_PRINT("Unknown message type received: %s", data);
      break;
  }

  return;
}