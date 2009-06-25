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

typedef enum {AUTH_USER, AUTH_ROOT} AuthType;

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
