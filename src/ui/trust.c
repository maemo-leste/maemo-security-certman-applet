/* -*- mode:c++; tab-width:4; c-basic-offset:4; -*- */

/**
   @file trust.c

   Trust settings modification dialog.
   <p>
   Copyright (c) 2005 Nokia. All rights reserved.

   @author  Karoliina T. Salminen <karoliina.t.salminen@nokia.com>
*/

#include <libosso.h>
#include <osso-log.h>
#define __HILDON_REMOTE_TEXTURE_H__
#include <hildon/hildon.h>

#include <unistd.h>

#include "i18n.h"
#include "osso-applet-certman.h"
#include "uiutils.h"
#include "uidefs.h"

/* Local interface */

/** Callback parameter for expired query dialog response */
typedef struct {
    CertificateExpiredResponseFunc callback;
    gpointer user_data;
} CallbackParameter;

static void _expired_dialog_response(GtkDialog* dialog,
                                     gint response_id,
                                     gpointer data);

static void _infonote_dialog_response(GtkDialog* dialog,
                                      gint response_id,
                                      gpointer data);

/* Implementation */


/*
 * Convenience function for showing a certain type of certificate expired dialog
 * for server certificates (cert_id = 0 used by default if needed for backword 
 * compatibility and means that the certificate in question is remote)
 */

gboolean 
certmanui_certificate_expired_with_name(
    gpointer window,
    CertmanUIExpiredDialogType type,
    const gchar* cert_name,
    CertificateExpiredResponseFunc callback,
    gpointer user_data)
{
    gint response_id = 0;
    GtkWidget* expired_dialog = NULL;
    GtkWidget* expired_label = NULL;
    gchar* buf = NULL;

    static CallbackParameter params;

    if (cert_name == NULL) {
        /* 
		 * Here we assume that this function is called for already known
         * expired cert.. 
		 */
        if (callback != NULL) 
			callback(TRUE, user_data);
        return TRUE;
    }

    expired_dialog = gtk_dialog_new_with_buttons
		(_("certman_ti_certificate_expired"),
		 GTK_WINDOW(window),
		 GTK_DIALOG_MODAL
		 | GTK_DIALOG_DESTROY_WITH_PARENT
		 | GTK_DIALOG_NO_SEPARATOR,
		 NULL);

    switch(type) {
		case CERTMANUI_EXPIRED_DIALOG_EXPIRED:
			buf = g_strdup_printf(_("cert_nc_expired"), cert_name);
			break;
		case CERTMANUI_EXPIRED_DIALOG_NOCA:
			buf = g_strdup_printf(_("cert_nc_nocatovalidate"));
			break;
		case CERTMANUI_EXPIRED_DIALOG_NOCA_EXPIRED:
			buf = g_strdup_printf
				(_("cert_nc_nocatovalidateand_expired"), cert_name);
			break;
	}
    expired_label = gtk_label_new(buf);
    g_free(buf);
    buf = NULL;
    gtk_label_set_line_wrap(GTK_LABEL(expired_label), TRUE);
    gtk_container_add(GTK_CONTAINER(GTK_DIALOG(expired_dialog)->vbox),
                      expired_label);

    /* Add buttons to the dialog */
    gtk_dialog_add_button(GTK_DIALOG(expired_dialog),
                          _("cert_bd_expired_ok"),
                          GTK_RESPONSE_OK);

    gtk_dialog_add_button(GTK_DIALOG(expired_dialog),
                          _("cert_bd_expired_cancel"),
                          GTK_RESPONSE_CANCEL);

    gtk_widget_show_all(expired_dialog);

    /* Fill CallbackParameters */
    params.callback = callback;
    params.user_data = user_data;

    if (callback == NULL)
    {
        while (response_id != GTK_RESPONSE_OK &&
               response_id != GTK_RESPONSE_CANCEL &&
               response_id != GTK_RESPONSE_DELETE_EVENT)
        {
            response_id = gtk_dialog_run(GTK_DIALOG(expired_dialog));
        }

        gtk_widget_destroy(expired_dialog);
        if (response_id == GTK_RESPONSE_OK) 
			return FALSE;

    } else {
        g_signal_connect(G_OBJECT(expired_dialog), 
						 "response",
                         G_CALLBACK(_expired_dialog_response), 
						 &params);
    }

    return TRUE;
}


/*
 *  Convenience interface for showing errors for remote certificate.
 */

gboolean 
certmanui_show_error_with_name_and_serial(gpointer window,
										  CertmanUIErrorType type,
										  const gchar* cert_name,
										  const gchar* cert_serial,
										  gpointer param,
										  CertificateExpiredResponseFunc callback,
										  gpointer user_data)
{
    gchar* use = NULL;
    GtkWidget* note = NULL;
    static CallbackParameter params;
    gchar* buf = NULL;

    if (cert_name == NULL && cert_serial == NULL)
    {
        ULOG_ERR("No certificate name or serial supplied");
        if (callback != NULL) 
			callback(TRUE, user_data);
        return TRUE;
    }

    /* Select string according to error type */
    switch(type)
		{
		case CERTMANUI_ERROR_NO_LONGER_TRUSTED:
			use = (gchar*)param;
			if (use != NULL) {
				use = _(use);
				buf = g_strdup_printf
					(_("cert_error_no_longer_trusted"),
					 cert_name, use);
			}
			break;

		case CERTMANUI_ERROR_NOT_VALID_SERVER_CERT:
			buf = g_strdup_printf
				(_("cert_error_not_valid_server_certificate"),
				 cert_name, cert_serial);
			break;

		case CERTMANUI_ERROR_NOT_VALID_USER_CERT:
			buf = g_strdup_printf
				(_("cert_error_not_valid_user_certificate"),
				 cert_name, cert_serial);
			break;

		case CERTMANUI_ERROR_UNABLE_TO_SAVE:
			buf = g_strdup_printf
				(_("cert_error_unable_to_save"),
				 cert_name, cert_serial);
			break;
    }

    /* Setup the dialog and handlers */
    note = hildon_note_new_information(GTK_WINDOW(window), buf);
    g_free(buf);
    buf = NULL;
    gtk_widget_show_all(note);

    /* Fill CallbackParameters */
    params.callback = callback;
    params.user_data = user_data;

    if (callback == NULL)
    {
        gtk_dialog_run(GTK_DIALOG(note));
        gtk_widget_destroy(note);

    } else {
        g_signal_connect(G_OBJECT(note), 
						 "response",
                         G_CALLBACK(_infonote_dialog_response), 
						 &params);
    }

    return TRUE;
}


static void _expired_dialog_response(GtkDialog* dialog,
                                     gint response_id,
                                     gpointer data)
{
    CallbackParameter* params = (CallbackParameter*)data;

    if (params == NULL)
    {
        ULOG_ERR("No params for _expired_dialog_response!");
        return;
    }

    if (params->callback != NULL)
    {
        /* Call callback */
        params->callback(response_id == GTK_RESPONSE_OK ? FALSE : TRUE,
                         params->user_data);
        gtk_widget_destroy(GTK_WIDGET(dialog));
    }
}


static void _infonote_dialog_response(GtkDialog* dialog,
                                      gint response_id,
                                      gpointer data)
{
    CallbackParameter* params = (CallbackParameter*)data;

    if (params == NULL)
    {
        ULOG_ERR("_infonote_dialog_response: wrong parameters");
    }

    params->callback(TRUE, params->user_data);
    gtk_widget_destroy(GTK_WIDGET(dialog));
}
