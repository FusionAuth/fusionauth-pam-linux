/*
 * pam_fusionauth_device_grant.c - PAM module for FusionAuth Device Authorization Grant
 * 
 * This module implements OAuth 2.0 Device Authorization Grant flow for PAM authentication
 * using FusionAuth as the identity provider.
 */

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <curl/curl.h>
#include <json-c/json.h>
#include "config.h"

#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_appl.h>

/* Device authorization response */
typedef struct {
    char *device_code;
    char *user_code;
    char *verification_uri;
    char *verification_uri_complete;
    int expires_in;
    int interval;
} device_auth_response_t;

/* Memory structure for CURL responses */
typedef struct {
    char *response;
    size_t size;
} memory_t;

/* Function prototypes */
static void free_device_response(device_auth_response_t *resp);
static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp);
static int initiate_device_flow(pam_handle_t *pamh, fa_config_t *config, device_auth_response_t *resp);
static int poll_for_token(pam_handle_t *pamh, fa_config_t *config, const char *device_code);
static int verify_user(pam_handle_t *pamh, const char *access_token, const char *username);

/* CURL write callback */
static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    memory_t *mem = (memory_t *)userp;

    char *ptr = realloc(mem->response, mem->size + realsize + 1);
    if (ptr == NULL) {
        pam_syslog(NULL, LOG_ERR, "Not enough memory (realloc returned NULL)");
        return 0;
    }

    mem->response = ptr;
    memcpy(&(mem->response[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->response[mem->size] = 0;

    return realsize;
}

/* Free device response structure */
static void free_device_response(device_auth_response_t *resp) {
    if (resp->device_code)
        free(resp->device_code);
    if (resp->user_code)
        free(resp->user_code);
    if (resp->verification_uri)
        free(resp->verification_uri);
    if (resp->verification_uri_complete)
        free(resp->verification_uri_complete);
}

/* Initiate device authorization flow */
static int initiate_device_flow(pam_handle_t *pamh, fa_config_t *config, device_auth_response_t *resp) {
    CURL *curl;
    CURLcode res;
    memory_t chunk;
    char url[512];
    char post_data[256];
    struct curl_slist *headers = NULL;
    int ret = PAM_AUTH_ERR;

    memset(resp, 0, sizeof(device_auth_response_t));
    chunk.response = malloc(1);
    chunk.size = 0;

    curl = curl_easy_init();
    if (!curl) {
        pam_syslog(pamh, LOG_ERR, "Failed to initialize CURL");
        return PAM_SERVICE_ERR;
    }

    /* Construct URL */
    snprintf(url, sizeof(url), "%s/oauth2/device_authorize", config->fusionauth_url);

    /* Construct POST data */
    snprintf(post_data, sizeof(post_data), "client_id=%s&scope=offline_access", config->client_id);

    /* Set headers */
    headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

    res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        pam_syslog(pamh, LOG_ERR, "CURL failed: %s", curl_easy_strerror(res));
        ret = PAM_SERVICE_ERR;
    } else {
        long http_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

        if (http_code == 200) {
            struct json_object *parsed_json;
            struct json_object *obj;

            parsed_json = json_tokener_parse(chunk.response);
            if (parsed_json) {
                if (json_object_object_get_ex(parsed_json, "device_code", &obj)) {
                    resp->device_code = strdup(json_object_get_string(obj));
                }

                if (json_object_object_get_ex(parsed_json, "user_code", &obj)) {
                    resp->user_code = strdup(json_object_get_string(obj));
                }

                if (json_object_object_get_ex(parsed_json, "verification_uri", &obj)) {
                    resp->verification_uri = strdup(json_object_get_string(obj));
                }

                if (json_object_object_get_ex(parsed_json, "verification_uri_complete", &obj)) {
                    resp->verification_uri_complete = strdup(json_object_get_string(obj));
                }

                if (json_object_object_get_ex(parsed_json, "expires_in", &obj)) {
                    resp->expires_in = json_object_get_int(obj);
                }

                if (json_object_object_get_ex(parsed_json, "interval", &obj)) {
                    resp->interval = json_object_get_int(obj);
                }

                json_object_put(parsed_json);
                ret = PAM_SUCCESS;
            } else {
                pam_syslog(pamh, LOG_ERR, "Failed to parse JSON response");
                ret = PAM_SERVICE_ERR;
            }
        } else {
            pam_syslog(pamh, LOG_ERR, "HTTP error: %ld", http_code);
            ret = PAM_AUTH_ERR;
        }
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(chunk.response);

    return ret;
}

/* Poll for token */
static int poll_for_token(pam_handle_t *pamh, fa_config_t *config, const char *device_code) {
    CURL *curl;
    CURLcode res;
    memory_t chunk;
    char url[512];
    char post_data[512];
    struct curl_slist *headers = NULL;
    time_t start_time = time(NULL);
    int poll_interval = config->poll_interval;
    int ret = PAM_AUTH_ERR;

    curl = curl_easy_init();
    if (!curl) {
        pam_syslog(pamh, LOG_ERR, "Failed to initialize CURL");
        return PAM_SERVICE_ERR;
    }

    /* Construct URL */
    snprintf(url, sizeof(url), "%s/oauth2/token", config->fusionauth_url);

    /* Construct POST data */
    snprintf(post_data, sizeof(post_data), 
             "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=%s&client_id=%s",
             device_code, config->client_id);

    /* Set headers */
    headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");

    /* Poll for token */
    time_t now = time(NULL);
    while (difftime(now, start_time) < config->timeout) {
        chunk.response = malloc(1);
        chunk.size = 0;

        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

        res = curl_easy_perform(curl);

        if (res == CURLE_OK) {
            long http_code = 0;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

            if (http_code == 200) {
                struct json_object *parsed_json;
                struct json_object *obj;

                parsed_json = json_tokener_parse(chunk.response);
                if (parsed_json) {
                    if (json_object_object_get_ex(parsed_json, "access_token", &obj)) {
                        pam_syslog(pamh, LOG_INFO, "Authentication successful");
                        ret = PAM_SUCCESS;
                        json_object_put(parsed_json);
                        free(chunk.response);
                        break;
                    }
                    json_object_put(parsed_json);
                }
            } else if (http_code == 400) {
                /* Check for authorization_pending or slow_down */
                struct json_object *parsed_json = json_tokener_parse(chunk.response);
                if (parsed_json) {
                    struct json_object *error_obj;
                    if (json_object_object_get_ex(parsed_json, "error", &error_obj)) {
                        const char *error = json_object_get_string(error_obj);
                        if (strcmp(error, "slow_down") == 0) {
                            poll_interval += 5;
                        } else if (strcmp(error, "authorization_pending") != 0) {
                            pam_syslog(pamh, LOG_ERR, "Authorization error: %s", error);
                            json_object_put(parsed_json);
                            free(chunk.response);
                            ret = PAM_AUTH_ERR;
                            break;
                        }
                    }
                    json_object_put(parsed_json);
                }
            }
        }

        free(chunk.response);
        sleep(poll_interval);
    }

    if (ret != PAM_SUCCESS && difftime(time(NULL), start_time) >= config->timeout) {
        pam_syslog(pamh, LOG_ERR, "Authentication timeout");
        ret = PAM_AUTH_ERR;
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    return ret;
}

/* PAM authentication handler */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    device_auth_response_t device_resp;
    int ret;
    const char *username;

    openlog("pam_fusionauth", LOG_PID, LOG_AUTHPRIV);

    /* Get username */
    ret = pam_get_user(pamh, &username, NULL);
    if (ret != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_ERR, "Failed to get username");
        closelog();
        return ret;
    }

    pam_syslog(pamh, LOG_INFO, "Authentication request for user: %s", username);

    // Use the default config for now
    fa_config_t *config = &DEFAULT_CONFIG;

    /* Initialize libcurl */
    curl_global_init(CURL_GLOBAL_DEFAULT);

    /* Initiate device flow */
    pam_syslog(pamh, LOG_INFO, "Device authorization flow initializing!");
    ret = initiate_device_flow(pamh, config, &device_resp);
    if (ret != PAM_SUCCESS) {
        free_config(config);
        curl_global_cleanup();
        closelog();
        return ret;
    }

    pam_syslog(pamh, LOG_INFO, "Device authorization flow initiated!");

    /* Display instructions to user */
    pam_info(pamh, "\n========================================");
    pam_info(pamh, "FusionAuth Device Authorization");
    pam_info(pamh, "========================================");
    pam_info(pamh, "Please visit: %s", device_resp.verification_uri);
    pam_info(pamh, "And enter code: %s", device_resp.user_code);

    pam_error(pamh, "\n========================================");
    pam_error(pamh, "FusionAuth Device Authorization");
    pam_error(pamh, "========================================");
    pam_error(pamh, "Please visit: %s", device_resp.verification_uri);
    pam_error(pamh, "And enter code: %s", device_resp.user_code);

    pam_syslog(pamh, LOG_INFO, "\n========================================");
    pam_syslog(pamh, LOG_INFO, "FusionAuth Device Authorization");
    pam_syslog(pamh, LOG_INFO, "========================================");
    pam_syslog(pamh, LOG_INFO, "Please visit: %s", device_resp.verification_uri);
    pam_syslog(pamh, LOG_INFO, "And enter code: %s", device_resp.user_code);

    if (device_resp.verification_uri_complete) {
        pam_info(pamh, "\nOr scan/visit: %s", device_resp.verification_uri_complete);
    }

    pam_info(pamh, "\nWaiting for authorization (timeout: %d seconds)...", config->timeout);
    pam_info(pamh, "========================================\n");

    /* Poll for token */
    ret = poll_for_token(pamh, config, device_resp.device_code);

    /* Cleanup */
    free_device_response(&device_resp);
    free_config(config);
    curl_global_cleanup();
    closelog();

    return ret;
}

///* PAM account management handler */
//PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
//    return PAM_SUCCESS;
//}
//
///* PAM session handler */
//PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
//    return PAM_SUCCESS;
//}
//
//PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
//    return PAM_SUCCESS;
//}
//
///* PAM password change handler */
//PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) {
//    return PAM_SERVICE_ERR;
//}
//
///* PAM module initialization */
//PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
//    return PAM_SUCCESS;
//}
