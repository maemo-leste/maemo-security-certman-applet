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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <glib.h>
#include <gtk/gtk.h>
#include <gdk/gdkx.h>
#include <glib/gprintf.h>
#include <openssl/err.h>
#include <libgnomevfs/gnome-vfs.h>

#include <X11/Xlib.h>
#include <X11/X.h>
#include <X11/Xatom.h>

#include <stdio.h>
#include <libosso.h>
#include <hildon/hildon.h>
// #include <osso-log.h>

#include <assert.h>
#include <libintl.h>
#include <locale.h>
#include <unistd.h>
#include <string.h>

#include <maemosec_common.h>

#include "osso-applet-certman.h"
#include "cm_dialogs.h"
#include "i18n.h"

static Window _get_window_property(Window xwindow, Atom atom);
static Atom _get_xatom_current_app_window(void);

extern osso_context_t *osso_global;
static osso_context_t *osso_aux = NULL;
static X509_STORE* root_store = NULL;

GMainLoop *mainloop = NULL;
GtkWidget *top_aux = NULL;

/* Display *dpy = NULL;  */

osso_context_t *osso_g = NULL;

/*
 * Send certificate name to get_privatekey by a global variable!
 */
gboolean _quit_clean(gpointer pointer);

#define DBUS_METHOD_MIME_OPEN       "mime_open"
#define DBUS_METHOD_TOP_APPLICATION "top_application"
#define DBUS_METHOD_GET_KEY_PASSWORD "get_key_password"

/* Define d-bus messages, to which application have to react */
/* For instance game application needs methods to start, continue, restart,
   close and pause the game */

#define OSSO_CM_EXECUTE_METHOD "certman_exec"

/* Testing d-bus messaging with displaying infoprint */
#define OSSO_CM_DISPLAY_INFOPRINT "certman_display_infoprint"

osso_return_t osso_rpc_cb(const gchar *interface,
                          const gchar *method,
                          GArray *args,
                          gpointer data,
                          osso_rpc_t *retval);

/**
   Set hardware event handler

   @param state Signals that are of interest
   @param cb Callback function.
   @param data Application specific data.
*/
gboolean set_hw_event_handler(osso_hw_state_t *state,
                              osso_hw_cb_f *cb,
                              gpointer data);


/**
    Handles hardware events.

    @todo Just a skeleton
    @param state State occured.
    @param data Application specific data.
*/
void hw_event_handler(osso_hw_state_t *state, gpointer data);

/**
   Initialize osso

   @param app Application specific data
   @returns TRUE on success, FALSE otherwise
*/

gboolean osso_init(osso_context_t **osso);

/**
   Deinitialize osso

   @returns TRUE on success, FALSE otherwise
*/

gboolean osso_deinit(osso_context_t *osso);

/* Depending on the state of hw, do something */
void hw_event_handler(osso_hw_state_t *state, gpointer data)
{
    (void) data;

    MAEMOSEC_DEBUG(1, "%s: shutdown %s save %s memlow %s sysinact %s devmode %d",
                   state->shutdown_ind?"on":"off",
                   state->save_unsaved_data_ind?"on":"off",
                   state->memory_low_ind?"on":"off",
                   state->system_inactivity_ind?"on":"off",
                   state->sig_device_mode_ind?"on":"off",
                   state->sig_device_mode_ind);

    if (state->shutdown_ind) {
        /* Rebooting */
        gtk_main_quit();
    }
    if (state->memory_low_ind) {
        /* Memory low */
    }
    if (state->save_unsaved_data_ind) {
        /* Battery low */
    }
    if (state->system_inactivity_ind) {
        /* Minimum activity */
    }
}

osso_return_t 
osso_rpc_cb(const gchar *interface,
			const gchar *method,
			GArray *args,
			gpointer data,
			osso_rpc_t *retval)
{
    gchar *fileuri = NULL;
    osso_rpc_t val;

	if (NULL == interface || NULL == method || NULL == args || NULL == retval || 0 == args->len) {
		certmanui_info(NULL, _("cert_error_install"));
		MAEMOSEC_ERROR("Invalid osso_rpc call, probably not a certificate file");
		return(OSSO_ERROR);
	}

    MAEMOSEC_DEBUG(1, "%s: '%s:%s' %d %p", __func__, interface, method, args->len);
	val = g_array_index(args, osso_rpc_t, 0);

    /* Catch the message and define what you want to do with it */

    if (g_ascii_strcasecmp(method, DBUS_METHOD_TOP_APPLICATION) == 0) {
        gtk_window_present(GTK_WINDOW(top_aux));
        return(OSSO_OK);
    }

    if (g_ascii_strcasecmp(method, DBUS_METHOD_GET_KEY_PASSWORD) == 0) {
		EVP_PKEY* pkey;
		gchar* password = NULL;
		maemosec_key_id key_id;
		osso_rpc_t name = g_array_index(args, osso_rpc_t, 1);
		int rc;

		MAEMOSEC_DEBUG(1, "Get password for key \"%s\"", val.value.s);

		if (1 < args->len) {
			name = g_array_index(args, osso_rpc_t, 1);
			// if (DBUS_TYPE_STRING == name.type)
			// 	cert_name_for_get_privatekey = name.value.s;
		}

		rc = maemosec_certman_str_to_key_id(val.value.s, key_id);
		if (0 == rc) {
			pkey = certmanui_get_privatekey(GTK_WINDOW(top_aux), key_id, &password,
											NULL, NULL);
			cert_name_for_get_privatekey = "";
            g_main_loop_quit(mainloop);
			if (NULL != pkey) {
				retval->type = DBUS_TYPE_STRING;
				retval->value.s = password;
				EVP_PKEY_free(pkey);
				return(OSSO_OK);
			} else {
				MAEMOSEC_ERROR("%s: no password", __func__);
				return(OSSO_ERROR);
			}
		} else {
			cert_name_for_get_privatekey = "";
			MAEMOSEC_ERROR("%s: invalid key id '%s'", __func__, val.value.s);
			return(OSSO_ERROR);
		}
    }

    if (g_ascii_strcasecmp(method, DBUS_METHOD_MIME_OPEN) == 0) {

        if ( (val.type == DBUS_TYPE_STRING)
             && (val.value.s != NULL) ) 
		{
            fileuri = g_strdup(val.value.s);
            MAEMOSEC_DEBUG(1, "fileuri came with mime_open request = \"%s\"",
                       fileuri);

            if (!certmanui_import_file(NULL, fileuri, NULL, NULL)) {
                MAEMOSEC_ERROR("Importing certificate failed");
                certmanui_info(NULL, _("cert_error_install"));
                g_main_loop_quit(mainloop);
                g_free(fileuri);
                return(OSSO_ERROR);
            }
            MAEMOSEC_DEBUG(1, "Imported");
            g_main_loop_quit(mainloop);
            g_free(fileuri);
            /*  gtk_main_quit(); */
            retval->type = DBUS_TYPE_BOOLEAN;
            retval->value.b = TRUE;
            return(OSSO_OK);
        } else {
			MAEMOSEC_ERROR("%s: invalid message", __func__);
		}
    }
    return(OSSO_ERROR);
}

/* 
 * Do initialization for OSSO, create osso context, set topping callback,
 * dbus-message handling callbacks, and hw-event callbacks. TODO: System
 * bus still not seem working well, so HW-event callbacks not tested 
 */
gboolean 
osso_init(osso_context_t **osso)
{
    osso_return_t ret;

    /* Init osso */
    MAEMOSEC_DEBUG(1, "Enter %s", __func__);
    *osso = osso_initialize("certman", PACKAGE_VERSION, FALSE, NULL);

    if (NULL == *osso) {
        MAEMOSEC_ERROR("Osso initialization failed");
        return FALSE;
    }
    g_assert(*osso);
    osso_g = *osso;

    /* RPC callback */
    ret = osso_rpc_set_cb_f(*osso,
                            "com.nokia.certman",
                            "/com/nokia/certman",
                            "com.nokia.certman",
                            (osso_rpc_cb_f *)osso_rpc_cb,
                            NULL);

    if (ret != OSSO_OK) {
        MAEMOSEC_ERROR("Could not set callback for receiving messages");
    }


    /* Set handling changes in HW states. Note: not tested */
    ret = osso_hw_set_event_cb(*osso,
                               NULL,
                               hw_event_handler,
                               NULL);

    if (ret != OSSO_OK) {
        MAEMOSEC_ERROR("Could not set callback for HW monitoring");
    }
	if (!gnome_vfs_init())
        MAEMOSEC_ERROR("%s: gnome_vfs_init returned FALSE", __func__);

    return TRUE;
}


/* Deinitialize osso specific data TODO:Check return values from osso */
gboolean osso_deinit(osso_context_t *osso)
{
    /* Unset callbacks */
    g_assert(osso);

	gnome_vfs_shutdown();

    osso_rpc_unset_cb_f(osso,
                        "com.nokia.certman",
                        "/com/nokia/certman",
                        "com.nokia.certman",
                        (osso_rpc_cb_f *)osso_rpc_cb,
						NULL);
    osso_hw_unset_event_cb(osso, NULL);

    /* Deinit osso */
    osso_deinitialize(osso);

    return TRUE;
}


int main(int argc, char* argv[]) 
{

    gint result=0;
    Atom atom_c;
    Window active_window;

    setlocale(LC_ALL, "");
    bindtextdomain(LANGDOMAIN, LOCALEDIR);
    bind_textdomain_codeset(LANGDOMAIN, "UTF-8");
    textdomain(LANGDOMAIN);

	ERR_print_errors_cb(report_openssl_error, NULL);

	result = maemosec_certman_open(&root_store);
	MAEMOSEC_DEBUG(1, "%s: maemosec_certman_open returned %d", __func__, result);

    gtk_init(&argc, &argv);
    mainloop = g_main_loop_new(NULL, FALSE);

    top_aux = gtk_window_new(GTK_WINDOW_TOPLEVEL);

    Window root_window = gdk_x11_get_default_root_xwindow();
    g_assert(root_window);

    atom_c = _get_xatom_current_app_window();
    MAEMOSEC_DEBUG(1, "Got current app window");

    if (atom_c) {
		active_window = _get_window_property(root_window, atom_c);
    } else {
        MAEMOSEC_ERROR("Failed to get active_window");
        return OSSO_ERROR;
    }

    g_assert(active_window);

    GdkWindow *gdk_active_window = gdk_window_foreign_new(active_window);
    top_aux->window = gdk_active_window;

    g_assert(gdk_active_window);
    g_assert(top_aux);

    if (!osso_init(&osso_aux) || NULL == osso_aux) {
		MAEMOSEC_ERROR("Failed to get osso context");
        return OSSO_ERROR;
    }

    osso_global = osso_aux;

    MAEMOSEC_DEBUG(1, "** starting cm_service, got osso context");

    g_main_loop_run(mainloop);

    fprintf(stderr, "cm_service: quitted gtk main loop\n");

	result = maemosec_certman_close(root_store);
	MAEMOSEC_DEBUG(1, "%s: maemosec_certman_close returned %d", __func__, result);
	
    return 0;
}


/* Borrowed from libwnck */
static Window 
_get_window_property(Window xwindow, Atom atom) 
{

    Atom type;
    gint format;
    gulong nitems;
    gulong bytes_after;
    Window *w=NULL;
    gint err, result;
    Window retval;

    gdk_error_trap_push();

    type = None;
    result = XGetWindowProperty(gdk_display,
                                xwindow,
                                atom,
                                0, 
								G_MAXLONG,
                                False, 
								XA_WINDOW, 
								&type, 
								&format, 
								&nitems,
                                &bytes_after, 
								(void*)&w);
    err = gdk_error_trap_pop();

    if (err != Success ||
        result != Success)
        return None;

    if (type != XA_WINDOW)
    {
        XFree (w);
        return None;
    }

    retval = *w;
    XFree (w);

    return retval;
}


static Atom 
_get_xatom_current_app_window (void) 
{

    /*  GdkDisplay* gdk_display = NULL;  */
    Atom atom_q;

    gdk_display = GDK_DISPLAY();

    gdk_error_trap_push();

    for (atom_q = 1; ; atom_q++) {
        gchar *s = XGetAtomName(gdk_display, (Atom)atom_q);
        /*  fprintf(stderr, "\nAtom (%ld): %s\n", (long)atom_q, s);  */
        if (s!=NULL) {
            /* (strcmp(s, "_MB_CURRENT_APP_WINDOW") == 0) */

            if (g_ascii_strcasecmp((gchar *)s, "_MB_CURRENT_APP_WINDOW") == 0){
                /*  fprintf(stderr, "Got the current window !!\n");
                    fprintf(stderr, "wanted atom: %s\n", s); */
                XFree(s);
                gdk_error_trap_pop();
                return atom_q;
            }
            XFree(s);
        }
        else {
            gdk_error_trap_pop();
            return 0;
        }

    }
}
