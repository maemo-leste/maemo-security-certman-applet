/* -*- mode:c; tab-width:4; c-basic-offset:4; -*- */

#ifndef CM_DIALOGS_H
#define CM_DIALOGS_H

/*
 * This is needed to make localtime_r visible
 */
#define _XOPEN_SOURCE

#include <gtk/gtk.h>
#define __HILDON_REMOTE_TEXTURE_H__
#include <hildon/hildon.h>

/* Size for the main dialog */
#define MIN_WIDTH               592
#define MIN_HEIGHT              332
#define MAX_WIDTH               800
#define MAX_HEIGHT              332

/* Size for the details dialog */
#define DETAILS_MIN_WIDTH       482
#define DETAILS_MIN_HEIGHT      338
#define DETAILS_MAX_WIDTH       800
#define DETAILS_MAX_HEIGHT      338

/* Size for the change password dialog */
#define PASSWD_MIN_WIDTH        352
#define PASSWD_MIN_HEIGHT       -1
#define PASSWD_MAX_WIDTH        800
#define PASSWD_MAX_HEIGHT       -1

/* Buffer size for various string routines */
#define BUFSIZE                 256

#define ICONSIZE                HILDON_ICON_PIXEL_SIZE_SMALL
#define REFRESH_INTERVAL        500

#define NAME_COL_WIDTH          340
#define ISSUE_COL_WIDTH         170
#define PURPOSE_COL_WIDTH       120

typedef enum {AUTH_USER, AUTH_ROOT} AuthType;

/* Response types */
typedef enum
{
    CM_RESPONSE_DELETE = 1,
    CM_RESPONSE_TRUST,
    CM_RESPONSE_PASSWORD,
    CM_RESPONSE_CLOSE,
    CM_RESPONSE_DETAILS,
    CM_RESPONSE_INSTALL
} CMResponseType;

GtkWidget* 
ui_create_main_dialog(gpointer window) ;

gchar*
ask_password(gpointer window, 
	     int test_password(void* data, gchar* pwd), 
	     void* data, 
	     const char* info);

int
report_openssl_error(const char* str, size_t len, void* u);

#endif
