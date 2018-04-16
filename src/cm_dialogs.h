/* -*- mode:c; tab-width:4; c-basic-offset:4; -*- 
 *
 * This file is part of maemo-security-certman-applet
 *
 * Copyright (C) 2009 Nokia Corporation and/or its subsidiary(-ies).
 *
 * Contact: Juhani Mäkelä <ext-juhani.3.makela@nokia.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 *
 */

#ifndef CM_DIALOGS_H
#define CM_DIALOGS_H

/*
 * This is needed to make localtime_r visible
 */
#define _XOPEN_SOURCE

#include <gtk/gtk.h>
#define __HILDON_REMOTE_TEXTURE_H__
#include <hildon/hildon.h>

typedef enum { AUTH_USER, AUTH_ROOT } AuthType;

GtkWidget *ui_create_main_dialog(gpointer window);

const gchar *ask_password(gpointer window,
			  gboolean object_is_cert,
			  int test_password(void *data, const gchar * pwd),
			  void *data, const char *info);

int report_openssl_error(const char *str, size_t len, void *u);

void certmanui_info(gpointer window, const char *text);

#endif
