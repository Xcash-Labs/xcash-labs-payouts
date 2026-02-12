#include "delegate_server_functions.h"

/* --------------------------------------------------------------------------------------------------------
  Name: server_receive_payout
  Description: Runs the code when the server receives the NODE_TO_BLOCK_VERIFIERS_CHECK_VOTE_STATUS message
  Parameters:

  MESSAGE - The message
----------------------------------------------------------------------------------------------------------- */
void server_receive_payout(const char* MESSAGE) {
  if (!MESSAGE || !*MESSAGE) {
    ERROR_PRINT("server_receive_payout: Invalid message parameter passed to server_receive_payout");
    return;
  }

  cJSON* root = cJSON_Parse(MESSAGE);
  if (!root) {
    const char* ep = cJSON_GetErrorPtr();
    ERROR_PRINT("server_receive_payout: cJSON parse error near: %s", ep ? ep : "(unknown)");
    return;
  }

  // Parsed fields
  char in_public_address[XCASH_WALLET_LENGTH + 1] = {0};
  char in_block_height[BLOCK_HEIGHT_LENGTH + 1] = {0};
  char in_delegate_wallet_address[XCASH_WALLET_LENGTH + 1] = {0};
  char in_outputs_hash[TRANSACTION_HASH_LENGTH + 1] = {0};
  char in_signature[XCASH_SIGN_DATA_LENGTH + 1] = {0};

  int ok = 1;
  ok &= json_get_string_into(root, "public_address", in_public_address, sizeof in_public_address, 1);
  ok &= json_get_string_into(root, "block_height", in_block_height, sizeof in_block_height, 1);
  ok &= json_get_string_into(root, "delegate_wallet_address", in_delegate_wallet_address, sizeof in_delegate_wallet_address, 1);
  ok &= json_get_string_into(root, "outputs_hash", in_outputs_hash, sizeof in_outputs_hash, 1);
  ok &= json_get_string_into(root, "XCASH_DPOPS_signature", in_signature, sizeof in_signature, 1);

  if (!ok) {
    ERROR_PRINT("server_receive_payout: Failed to parse json fields in server_receive_payout");
    cJSON_Delete(root);
    return;
  }

  uint64_t in_num_block_height = strtoull(in_block_height, NULL, 10);
  uint64_t conf = (uint64_t)(CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW + SAFE_CONFIRMATION_MARGIN);
  uint64_t pass_block_height = (in_num_block_height > conf) ? (in_num_block_height - conf) : 0;
  size_t entries_count = 0;
  {
    cJSON* jcnt = cJSON_GetObjectItemCaseSensitive(root, "entries_count");
    if (!jcnt || !cJSON_IsNumber(jcnt)) {
      ERROR_PRINT("server_receive_payout: Missing/invalid 'entries_count'");
      cJSON_Delete(root);
      return;
    }

    double v = jcnt->valuedouble;
    if ((v < 0.0) || v > (double)MAX_PROOFS_PER_DELEGATE_HARD) {
      ERROR_PRINT("server_receive_payout: 'entries_count' out of range");
      cJSON_Delete(root);
      return;
    }

    uint64_t u = (uint64_t)v;
    double diff = v - (double)u;
    if (diff < -1e-9 || diff > 1e-9) {
      ERROR_PRINT("server_receive_payout: 'entries_count' must be an integer JSON number");
      cJSON_Delete(root);
      return;
    }

    entries_count = (size_t)u;
  }

  if (entries_count == 0) {
    INFO_PRINT("server_receive_payout: entries_count == 0; marking found_blocks < %" PRIu64
               " as processed and exiting", pass_block_height);
    int is_ok = mark_found_blocks_processed_up_to(pass_block_height);
    cJSON_Delete(root);
    if (is_ok == XCASH_ERROR) {
      ERROR_PRINT("server_receive_payout: error calling mark_found_blocks_processed_up_to");
    }
    return;
  }

  // outputs (array)
  cJSON* outs = cJSON_GetObjectItemCaseSensitive(root, "outputs");
  if (!outs || !cJSON_IsArray(outs)) {
    ERROR_PRINT("server_receive_payout: Missing/invalid 'outputs' array");
    cJSON_Delete(root);
    return;
  }

  size_t n = (size_t)cJSON_GetArraySize(outs);
  if (entries_count != n) {
    WARNING_PRINT("server_receive_payout: entries_count (%zu) != outputs length (%zu) — using min(outputs length, MAX_PROOFS_PER_DELEGATE_HARD)",
                  entries_count, n);
    if (n > MAX_PROOFS_PER_DELEGATE_HARD) {
      WARNING_PRINT("server_receive_payout: outputs length exceeds hard limit (%d), truncating", MAX_PROOFS_PER_DELEGATE_HARD);
      n = MAX_PROOFS_PER_DELEGATE_HARD;
    }
    entries_count = n;
  }

  payout_output_t* parsed = NULL;
  if (entries_count > 0) {
    parsed = (payout_output_t*)calloc(entries_count, sizeof(*parsed));
    if (!parsed) {
      ERROR_PRINT("server_receive_payout: OOM allocating outputs array");
      cJSON_Delete(root);
      return;
    }
  }

  // Iterate and extract each element: { "a": "<addr>", "v": <number> }
  size_t i = 0;
  for (cJSON* elem = outs->child; elem && i < entries_count; elem = elem->next, ++i) {
    if (!cJSON_IsObject(elem)) {
      ERROR_PRINT("server_receive_payout: outputs[%zu] is not an object", i);
      free(parsed);
      cJSON_Delete(root);
      return;
    }

    // address
    cJSON* ja = cJSON_GetObjectItemCaseSensitive(elem, "a");
    if (!ja || !cJSON_IsString(ja) || !ja->valuestring) {
      ERROR_PRINT("server_receive_payout: outputs[%zu].a missing/invalid", i);
      free(parsed);
      cJSON_Delete(root);
      return;
    }
    size_t alen = strlen(ja->valuestring);
    if (alen >= sizeof(parsed[i].a)) {
      ERROR_PRINT("server_receive_payout: outputs[%zu].a too long (%zu >= %zu)", i, alen, sizeof(parsed[i].a));
      free(parsed);
      cJSON_Delete(root);
      return;
    }
    memcpy(parsed[i].a, ja->valuestring, alen + 1);

    // amount (uint64_t from JSON string)
    cJSON* jv = cJSON_GetObjectItemCaseSensitive(elem, "v");
    if (!jv || !cJSON_IsString(jv) || !jv->valuestring || jv->valuestring[0] == '\0') {
      ERROR_PRINT("server_receive_payout: outputs[%zu].v missing/invalid (must be string)", i);
      free(parsed);
      cJSON_Delete(root);
      return;
    }

    /* strict decimal parse */
    errno = 0;
    char* end = NULL;
    unsigned long long tmp = strtoull(jv->valuestring, &end, 10);
    if (errno == ERANGE || end == jv->valuestring || *end != '\0') {
      ERROR_PRINT("server_receive_payout: outputs[%zu].v invalid uint64 string '%s'", i, jv->valuestring);
      free(parsed);
      cJSON_Delete(root);
      return;
    }

    parsed[i].v = (uint64_t)tmp;
  }

  // Cleanup
  cJSON_Delete(root);

  if (strlen(in_outputs_hash) != TRANSACTION_HASH_LENGTH || !is_hex_string(in_outputs_hash)) {
    ERROR_PRINT("server_receive_payout: outputs_hash must be %d hex chars", TRANSACTION_HASH_LENGTH);
    free(parsed);
    return;
  }

  if (strcmp(in_delegate_wallet_address, xcash_wallet_public_address) != 0) {
    ERROR_PRINT("server_receive_payout: Payout transaction is not for this delegate");
    free(parsed);
    return;
  }

  uint8_t out_hash[SHA256_HASH_SIZE];
  outputs_digest_sha256(parsed, entries_count, out_hash);
  char out_hash_hex[TRANSACTION_HASH_LENGTH + 1];
  bin_to_hex(out_hash, SHA256_HASH_SIZE, out_hash_hex);
  if (strcmp(out_hash_hex, in_outputs_hash) != 0) {
    ERROR_PRINT("server_receive_payout: outputs_hash mismatch for payout trans");
    free(parsed);
    return;
  }

  char ck_block_hash[BLOCK_HASH_LENGTH + 1] = {0};
  uint64_t reward_atomic = 0;
  uint64_t ts_epoch = 0;
  bool is_orphan = false;
  uint64_t block_create_height = strtoull(in_block_height, NULL, 10) - 1;
  int rc = get_block_info_by_height(block_create_height, ck_block_hash, sizeof(ck_block_hash), &reward_atomic, &ts_epoch, &is_orphan);
  if (rc != XCASH_OK) {
    ERROR_PRINT("server_receive_payout: get_block_info_by_height(%" PRIu64 ") failed", block_create_height);
    free(parsed);
    return;
  }

  char* sign_str = NULL;
  {
    const char* fmt_sign = "SEED_TO_NODES_PAYOUT|%s|%s|%s|%zu|%s";
    int need = snprintf(NULL, 0, fmt_sign,
                        in_block_height,
                        ck_block_hash,
                        in_delegate_wallet_address,
                        entries_count,
                        in_outputs_hash);
    if (need < 0) {
      ERROR_PRINT("server_receive_payout: Failed to size signable string");
      free(parsed);
      return;
    }
    size_t len = (size_t)need + 1;
    sign_str = (char*)malloc(len);
    if (!sign_str) {
      ERROR_PRINT("server_receive_payout: malloc(%zu) failed for signable string", len);
      free(parsed);
      return;
    }
    int wrote = snprintf(sign_str, len, fmt_sign,
                         in_block_height, ck_block_hash, in_delegate_wallet_address, entries_count, in_outputs_hash);
    if (wrote < 0 || (size_t)wrote >= len) {
      ERROR_PRINT("server_receive_payout: snprintf(write) failed or truncated");
      free(parsed);
      free(sign_str);
      return;
    }
  }

  // Prepare wallet verify request
  const char* HTTP_HEADERS[] = {"Content-Type: application/json", "Accept: application/json"};
  const size_t HTTP_HEADERS_LENGTH = sizeof(HTTP_HEADERS) / sizeof(HTTP_HEADERS[0]);
  char request[MEDIUM_BUFFER_SIZE * 2] = {0};
  char response[MEDIUM_BUFFER_SIZE] = {0};

  snprintf(request, sizeof(request),
           "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"verify\",\"params\":{"
           "\"data\":\"%s\","
           "\"address\":\"%s\","
           "\"signature\":\"%s\"}}",
           sign_str, in_public_address, in_signature);

  if (send_http_request(response, sizeof(response), XCASH_WALLET_IP, "/json_rpc", XCASH_WALLET_PORT,
   "POST", HTTP_HEADERS, HTTP_HEADERS_LENGTH, request, HTTP_TIMEOUT_SETTINGS) <= 0) {
    ERROR_PRINT("server_receive_payout: HTTP request failed trying to check signature");
    free(parsed);
    free(sign_str);
    return;
  }

  char result[8] = {0};
  int parsed_ok = parse_json_data(response, "result.good", result, sizeof(result));
  if (parsed_ok != 1) {
    ERROR_PRINT("server_receive_payout: verify response missing/invalid");
    free(parsed);
    free(sign_str);
    return;
  }
  if (strcmp(result, "true") != 0) {
    ERROR_PRINT("server_receive_payout: signature verification failed (result.good=%s)", result);
    free(parsed);
    free(sign_str);
    return;
  }

  uint64_t unlocked = 0;
  if (get_unlocked_balance(&unlocked) != XCASH_OK) {
    ERROR_PRINT("server_receive_payout: get_unlocked_balance failed");
    free(parsed);
    free(sign_str);
    return;
  }

  INFO_PRINT("server_receive_payout: Unlocked balance: %" PRIu64 " atomic (%.6f XCK)", unlocked,
    (double)unlocked / (double)XCASH_ATOMIC_UNITS);
  if(compute_payouts_due(parsed, pass_block_height, unlocked, entries_count) == XCASH_ERROR) {
    ERROR_PRINT("compute_payout_due failed");
    free(parsed);
    free(sign_str);
    return;
  }

  free(parsed);
  free(sign_str);

  if (run_payout_sweep_simple(unlocked) != XCASH_OK) {
    ERROR_PRINT("run_payout_sweep_simple failed");
  }

  return;
}