/*
 * pam_fusionauth_device_grant.c - PAM module for FusionAuth Device Authorization Grant
 * 
 * This module implements OAuth 2.0 Device Authorization Grant flow for PAM authentication
 * using FusionAuth as the identity provider.
 */

#define CONFIG_FILE "/etc/pam_fusionauth.conf"
#define DEFAULT_TIMEOUT 300
#define DEFAULT_INTERVAL 5

/* Configuration structure */
typedef struct {
    char *fusionauth_url;
    char *client_id;
    int timeout;
    int poll_interval;
} fa_config_t;

extern fa_config_t DEFAULT_CONFIG;

/* Function prototypes (unused because the Makefile has -Wall and compiles in order */
bool load_config(fa_config_t *config);
void free_config(fa_config_t *config);
