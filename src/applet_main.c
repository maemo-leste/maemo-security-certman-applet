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

#define _XOPEN_SOURCE
#include <glib.h>
#include <gtk/gtk.h>

#include <libosso.h>
// #include <osso-log.h>

#include <assert.h>
#include <string.h>
#include <hildon/hildon.h>
#include <openssl/err.h>
#include <maemosec_common.h>
#include <maemosec_certman.h>

#define NAME "Certman"
/* Prototypes for execute and reset */
#include <hildon-cp-plugin/hildon-cp-plugin-interface.h>

#include "osso-applet-certman.h"
#include "cm_dialogs.h"
#include "i18n.h"

const maemosec_key_id MAEMOSEC_EMPTY_KEY_ID =
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

static void _quit(gpointer data);

/* Implementation */

GtkWidget *main_dialog = NULL;

/* See settings_internalize.c */
extern osso_context_t *osso_global;
X509_STORE *root_store = NULL;

/**
 * Definition of execute interface for Certman applet, used by any calling
 * application (primary user: Control Panel application).
 *
 * @param osso  osso context of the calling application.
 * @param data  Pointer to gtk window of the calling application.
 * @param user_activated   Flag indicating calling mode, either normal user
 *                         activation or system activation.
 */

osso_return_t
execute(osso_context_t * osso, gpointer data, gboolean user_activated)
{
	gint ret = -1, tret = 0;

	MAEMOSEC_DEBUG(1, "Enter %s (built %s %s)", __func__, __DATE__,
		       __TIME__);

	// setlocale(LC_ALL, "");
	bindtextdomain(LANGDOMAIN, LOCALEDIR);
	// bind_textdomain_codeset(LANGDOMAIN, "UTF-8");
	// textdomain(LANGDOMAIN);

	ERR_print_errors_cb(report_openssl_error, NULL);

	/* Get configuration from SettingsInternalize */

	if (osso == NULL) {
		MAEMOSEC_ERROR
		    ("Applet execute() called with NULL osso context.. aborting");
		return OSSO_ERROR;
	}

	MAEMOSEC_DEBUG(1, "Osso context %p, data %p, user_activated=%s",
		       osso, data, user_activated ? "yes" : "no");
	osso_global = osso;

	ret = maemosec_certman_open(&root_store);
	MAEMOSEC_DEBUG(1, "maemosec_certman_open returned %d", ret);

	/* Create the main dialog and refresh it */
	main_dialog = ui_create_main_dialog(data);

	if (main_dialog == NULL) {
		MAEMOSEC_ERROR("Unable to create applet dialog, exiting..");
		return OSSO_ERROR;
	}

	/* Run dialog */
	while (ret != GTK_RESPONSE_DELETE_EVENT && ret != GTK_RESPONSE_CANCEL) {
		ret = gtk_dialog_run(GTK_DIALOG(main_dialog));
	}

	/* Quit */
	_quit(main_dialog);

	/* If response from dialog was ok, return tret */
	if (ret == GTK_RESPONSE_OK) {
		/* osso_cp_plugin_ok(osso, NAME); */
		return tret;
	}

	return OSSO_OK;
}

static void _quit(gpointer dialog)
{
	gint ret;
	/* Delete ui */
	MAEMOSEC_DEBUG(1, "Enter %s", __func__);
	if (dialog != NULL) {
		gtk_widget_hide_all(dialog);
		gtk_widget_destroy(dialog);
		// ui_destroy();
	}

	/* Destroy SettingsDatabase */
	ret = maemosec_certman_close(root_store);
	MAEMOSEC_DEBUG(1, "maemosec_certman_close returned %d", ret);
}
