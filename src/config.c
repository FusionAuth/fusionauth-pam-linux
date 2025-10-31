/*
 * pam_fusionauth_device_grant.c - PAM module for FusionAuth Device Authorization Grant
 * 
 * This module implements OAuth 2.0 Device Authorization Grant flow for PAM authentication
 * using FusionAuth as the identity provider.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include "config.h"

fa_config_t DEFAULT_CONFIG = {"http://192.168.64.1:9011", "85a03867-dccf-4882-adde-1a79aeec50df", DEFAULT_TIMEOUT, DEFAULT_INTERVAL};

/* Load configuration from file */
bool load_config(fa_config_t *config) {
    FILE *fp;
    char line[512];
    
    memset(config, 0, sizeof(fa_config_t));
    config->timeout = DEFAULT_TIMEOUT;
    config->poll_interval = DEFAULT_INTERVAL;

    fp = fopen(CONFIG_FILE, "r");
    if (fp == NULL) {
        syslog(LOG_ERR, "pam_fusionauth: Cannot open config file %s", CONFIG_FILE);
        return false;
    }

    while (fgets(line, sizeof(line), fp)) {
        char *key, *value;
        
        /* Skip comments and empty lines */
        if (line[0] == '#' || line[0] == '\n') {
            continue;
        }

        /* Remove trailing newline */
        line[strcspn(line, "\n")] = 0;

        key = strtok(line, "=");
        value = strtok(NULL, "=");

        if (key == NULL || value == NULL) {
            continue;
        }

        /* Trim whitespace */
        while (*value == ' ' || *value == '\t') {
            value++;
        }

        if (strcmp(key, "fusionauth_url") == 0) {
            config->fusionauth_url = strdup(value);
        } else if (strcmp(key, "client_id") == 0) {
            config->client_id = strdup(value);
        } else if (strcmp(key, "timeout") == 0) {
            config->timeout = atoi(value);
        } else if (strcmp(key, "poll_interval") == 0) {
            config->poll_interval = atoi(value);
        }
    }

    fclose(fp);

    /* Validate required configuration */
    if (config->fusionauth_url == NULL || config->client_id == NULL) {
        syslog(LOG_ERR, "pam_fusionauth: Missing required configuration");
        free_config(config);
        return false;
    }

    return true;
}

/* Free configuration structure */
void free_config(fa_config_t *config) {
    if (config == &DEFAULT_CONFIG) {
        return;
    }

    if (config->fusionauth_url) {
        free(config->fusionauth_url);
    }

    if (config->client_id) {
        free(config->client_id);
    }
}
