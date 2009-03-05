/**
   @file dbus.c

   DBUS handling
   <p>

   Copyright (c) 2005-2006 Nokia. All rights reserved.

   Contact: Jakub Pavelek <jakub.pavelek@nokia.com>
*/

#define _XOPEN_SOURCE 

#include <gtk/gtk.h>
#include <gconf/gconf-client.h>
#include <libosso.h>
#include <log-functions.h>
#include <unistd.h>
#include <glib.h>
#include <glib/gprintf.h>
#include <string.h>

#include "dbus.h"
#include "../ui/osso-applet-certman.h"

extern GtkDialog *top_aux;
extern GMainLoop *mainloop;

static gboolean import_called = FALSE;
osso_context_t *osso_g = NULL;

gboolean _import_file_stub(void);
gboolean _quit_clean(gpointer pointer);

gint dbus_req_handler(const gchar *interface, const gchar *method,
                      GArray *arguments, gpointer data,
                      osso_rpc_t *retval)
{
    (void) interface;
    return dbus_message_handler(method, arguments, data, retval);
}

gint dbus_message_handler(const gchar *method, GArray *arguments,
                          gpointer data, osso_rpc_t *retval)
{
    gchar *fileuri = NULL;

    osso_rpc_t val = g_array_index(arguments, osso_rpc_t, 0);

    (void) arguments;
    g_assert(method);

    MAEMOSEC_DEBUG(1, "dbus: method '%s' called", method);

    /* Catch the message and define what you want to do with it */

    if (g_ascii_strcasecmp(method, DBUS_METHOD_TOP_APPLICATION) == 0) {

        MAEMOSEC_DEBUG(1, "Got method 'mime_open' with method '%s'",
                   DBUS_METHOD_TOP_APPLICATION);
        gtk_window_present(GTK_WINDOW(top_aux));
        return OSSO_OK;
    }

    if (g_ascii_strcasecmp(method, DBUS_METHOD_MIME_OPEN) == 0) {
        MAEMOSEC_DEBUG(1, "Got method 'mime_open' with method '%s'",
                   DBUS_METHOD_MIME_OPEN);
        if ( (val.type == DBUS_TYPE_STRING)
             && (val.value.s != NULL) ) {


            fileuri = g_strdup(val.value.s);
            MAEMOSEC_DEBUG(1, "fileuri came with mime_open request = \"%s\"",
                       fileuri);


            _import_file_stub();

            certmanui_import_file(GTK_WINDOW(top_aux), fileuri, NULL, NULL);

            g_free(fileuri);

            gtk_main_quit();

            /*
              guint timeout;
              timeout = g_timeout_add(1000, _quit_clean, top_aux);
              g_signal_connect(top_aux, "delete_event",
              G_CALLBACK(g_source_remove),
              GUINT_TO_POINTER(timeout));
            */
            retval->type = DBUS_TYPE_BOOLEAN;
            retval->value.b = TRUE;
            return OSSO_OK;
        }

    } else {
    }

    return DBUS_TYPE_INVALID;
}


/* Depending on the state of hw, do something */
void hw_event_handler(osso_hw_state_t *state, gpointer data)
{
    (void) data;

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

osso_return_t osso_rpc_cb(const gchar *interface,
                          const gchar *method,
                          GArray *args,
                          gpointer data,
                          osso_rpc_t *retval)
{
    (void) interface;

    gchar *fileuri = NULL;
    gchar buf[128];
    guint cert_id = 0;
    GSList *new_certs = NULL, *node = NULL;
    GConfClient *client;

    osso_rpc_t val = g_array_index(args, osso_rpc_t, 0);

    (void) args;
    g_assert(method);

    MAEMOSEC_DEBUG(1, "dbus: method '%s' called", method);

    /* Catch the message and define what you want to do with it */

    if (g_ascii_strcasecmp(method, DBUS_METHOD_TOP_APPLICATION) == 0) {

        MAEMOSEC_DEBUG(1, "Got dbus message with method '%s'",
                   DBUS_METHOD_TOP_APPLICATION);
        gtk_window_present(GTK_WINDOW(top_aux));
        return OSSO_OK;
    }

    if (g_ascii_strcasecmp(method, DBUS_METHOD_MIME_OPEN) == 0) {

        MAEMOSEC_DEBUG(1, "Got dbus message with method '%s'",
                   DBUS_METHOD_MIME_OPEN);
        if ( (val.type == DBUS_TYPE_STRING)
             && (val.value.s != NULL) ) {
            fileuri = g_strdup(val.value.s);
            MAEMOSEC_DEBUG(1, "fileuri came with mime_open request = \"%s\"",
                       fileuri);

            if (import_called == FALSE) {
                import_called = TRUE;
                _import_file_stub();

                if (!certmanui_import_file(NULL, fileuri, &cert_id, &new_certs)) {
                    ULOG_ERR("Importing certificate failed");
                    g_main_loop_quit(mainloop);
                    g_free(fileuri);
                    return OSSO_ERROR;
                }
                if (new_certs != NULL || cert_id != 0) {

                    MAEMOSEC_DEBUG(1, "The following new cids came:");
                    for (node = new_certs; node; node = node->next) {
                        MAEMOSEC_DEBUG(1, "cid = %d", *(guint *)node->data);
                        g_sprintf(buf, "%d", *(guint *)node->data);
                        node->data = g_strndup(buf, strlen(buf));

                    }
                    if (cert_id != 0) {
                        MAEMOSEC_DEBUG(1, "Got new cert_id = %d", (guint)cert_id);
                        g_sprintf(buf, "%d", cert_id);
                        new_certs = g_slist_prepend(new_certs, g_strndup(buf, strlen(buf)));
                    }

                    g_type_init();
                    client = gconf_client_get_default();
                    if (client == NULL) {
                        ULOG_ERR("Unable to get GConf client.");
                        /* returning OK anyways, since the certificate was imported */
                        g_free(fileuri);
                        g_main_loop_quit(mainloop);
                        return OSSO_OK;
                    }

                    gconf_client_set_list(client,
                                          GCONF_NEW_CERTS_KEY,
                                          GCONF_VALUE_STRING,
                                          new_certs,
                                          NULL);
                    gconf_client_suggest_sync(client, NULL);
                    if (new_certs != NULL) g_slist_free(new_certs);
                    g_object_unref(client);
                }

            }
            g_free(fileuri);
            g_main_loop_quit(mainloop);
            /*  gtk_main_quit(); */

            retval->type = DBUS_TYPE_BOOLEAN;
            retval->value.b = TRUE;
            return OSSO_OK;
        }
    }
    return OSSO_ERROR;
}

/* Do initialization for OSSO, create osso context, set topping callback,
   dbus-message handling callbacks, and hw-event callbacks. TODO: System
   bus still not seem working well, so HW-event callbacks not tested */
gboolean osso_init(osso_context_t **osso)
{
    osso_return_t ret;

    /* Init osso */
    osso_log(LOG_INFO, "Initializing osso");
    *osso = osso_initialize("certman",
                            "1.0.29", TRUE, NULL);

    if (*osso==NULL) {
        osso_log(LOG_ERR, "Osso initialization failed");
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
        osso_log(LOG_ERR, "Could not set callback for receiving messages");
    }


    /* Set handling changes in HW states. Note: not tested */
    ret = osso_hw_set_event_cb(*osso,
                               NULL,
                               hw_event_handler,
                               NULL);

    if (ret != OSSO_OK) {
        osso_log(LOG_ERR, "Could not set callback for HW monitoring");
    }

    return TRUE;
}


/* Deinitialize osso specific data TODO:Check return values from osso */
gboolean osso_deinit(osso_context_t *osso)
{
    /* Unset callbacks */
    g_assert(osso);

    osso_rpc_unset_cb_f(osso,
                        "com.nokia.certman",
                        "/com/nokia/certman",
                        "com.nokia.certman",
                        dbus_req_handler, NULL);

    osso_hw_unset_event_cb(osso, NULL);

    /* Deinit osso */
    osso_deinitialize(osso);

    return TRUE;
}

gboolean _import_file_stub() {
    MAEMOSEC_DEBUG(1, "Mime_open stub executed");
    return TRUE;
}
