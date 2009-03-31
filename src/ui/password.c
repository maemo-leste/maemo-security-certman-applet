/* -*- mode:c++; tab-width:4; c-basic-offset:4; -*- */
/**
   @file password.c

   Password changing dialog.
   <p>
   Copyright (c) 2005 Nokia. All rights reserved.

   @author  Karoliina T. Salminen <karoliina.t.salminen@nokia.com>
*/

#define _XOPEN_SOURCE

#include <libosso.h>
#include <osso-log.h>
#include <string.h>
#include <hildon/hildon.h>

#include "uiutils.h"
#include "uidefs.h"
#include "i18n.h"
#include "osso-applet-certman.h"
#include "password.h"

/* Local interface */

#define EVP_PKEY_dup(pkey)                                              \
    (EVP_PKEY *)ASN1_dup((int (*)())i2d_PrivateKey,                     \
                         (char *(*)())d2i_AutoPrivateKey,(char *)pkey)
#define MIN_PASSWD_LENGTH 5

/** Callback parameter for password query dialog response */
typedef struct {
    EVP_PKEY* got_key;
    maemosec_key_id cert_id;
    PrivateKeyResponseFunc callback;
    GtkWidget* passwd_entry;
    gpointer user_data;
} CallbackParameter;

/**
   Callback, which is called, when text in password entry has changed.

   @param editable      The password entry
   @param user_data     The OK-button.
*/
static void _passwd_text_changed(GtkEditable *editable,
                                 gpointer user_data);

/**
   Handler for the timeout. Decreases the left time and enables the
   OK-button, if appropriate.

   @param user_data     The OK-button.
*/
static gboolean _timeout_handler(gpointer user_data);


/**
   Handler for handling the response from password query.

   @param dialog        Dialog, which got the response
   @param response_id   Response id from the dialog.
   @param data          CallbackParameter
*/
static void _password_dialog_response(GtkDialog* dialog,
                                      gint response_id,
                                      gpointer data);

/**
   Password changing function.

   @param window        Window to display password change dialog in.
   @param cert_id       Certificate ID.
   @param key_id        Key ID.
   @param new_key_id    New key ID.
   @param new_passwd    Placeholder for new password.
*/
static gboolean _change_password(gpointer window, maemosec_key_id cert_id,
                                 maemosec_key_id key_id, maemosec_key_id* new_key_id,
                                 gchar** new_passwd);

/* Implementation */

guint timeout_id = 0;
gint time_left = -1; /* time_left < 0 => terminate timeout */

gint delays[] = {0, 1, 30, 300, -1};
gint current_delay = 0;

GtkWidget* enter_passwd_dialog = NULL;

/* defined in importexport.c */
extern gboolean close_store_on_exit;


EVP_PKEY* 
certmanui_get_privatekey(gpointer window, 
						 maemosec_key_id cert_id,
						 gchar** password,
						 PrivateKeyResponseFunc callback,
						 gpointer user_data)
{
    X509* cert = NULL;
    gint response_id = 0;
	char key_id_str [MAEMOSEC_KEY_ID_STR_LEN];

    static CallbackParameter params;

	maemosec_certman_key_id_to_str(cert_id, key_id_str, sizeof(key_id_str));
	MAEMOSEC_DEBUG(1, "%s for %s", __func__, key_id_str);

    /* Fill in params struct */
    params.got_key = NULL;
    memcpy(params.cert_id, cert_id, sizeof(params.cert_id));
    params.callback = callback;
    params.user_data = user_data;

    /* Create password dialog */
    enter_passwd_dialog = create_password_dialog(window,
                                                 cert,
                                                 _("cert_ti_enter_password"),
												 "",
                                                 _("cert_ia_password"),
                                                 "OK", // [wdgt_bd_done]
                                                 "",
                                                 &params.passwd_entry,
                                                 FALSE, 1);
    gtk_widget_show_all(enter_passwd_dialog);

    g_signal_connect(G_OBJECT(enter_passwd_dialog), "response",
                     G_CALLBACK(_password_dialog_response), &params);

    /* If there is no callback, then block, until we got definite answer */
    if (callback == NULL)
    {
        response_id = GTK_RESPONSE_OK;
        while(response_id == GTK_RESPONSE_OK &&
              params.got_key == NULL)
        {
            response_id = gtk_dialog_run(GTK_DIALOG(enter_passwd_dialog));
        }

        /* Save password, if user is interested in it */

        if (password != NULL && response_id == GTK_RESPONSE_OK)
        {
            *password = g_strdup(gtk_entry_get_text(
                                     GTK_ENTRY(params.passwd_entry)));
        }

        gtk_widget_destroy(enter_passwd_dialog);
        enter_passwd_dialog = NULL;
    }

    return params.got_key;
}





void 
certmanui_cancel_privatekey(void)
{
    if (enter_passwd_dialog != NULL)
    {
        gtk_dialog_response(GTK_DIALOG(enter_passwd_dialog),
                            GTK_RESPONSE_CANCEL);
    }
}


static void 
_password_dialog_response(GtkDialog* dialog,
						  gint response_id,
						  gpointer data)
{
    CallbackParameter* params = (CallbackParameter*)data;
    gchar* passwd = NULL;
	int rc;

    if (params == NULL)
    {
        ULOG_ERR("No params for _password_dialog_response!");
        return;
    }

    if (response_id == GTK_RESPONSE_OK)
    {
        /* Try to get the key with given password */
        passwd = g_strdup(
            gtk_entry_get_text(GTK_ENTRY(params->passwd_entry)));

		MAEMOSEC_DEBUG(1, "Testing password '%s' for '%s'", passwd,
					   dynhex(params->cert_id, MAEMOSEC_KEY_ID_LEN));

		rc = maemosec_certman_retrieve_key(params->cert_id, &params->got_key, passwd);
        if (0 == rc)
        {
			MAEMOSEC_DEBUG(1, "Success: password is correct");
            /* Make duplicate of the key */
            /* params->got_key = EVP_PKEY_dup(params->got_key); */
        } else {
            /* Password was wrong */
			MAEMOSEC_DEBUG(1, "Wrong password, sorry!");

            /* Clear entry and show infonote */
            gtk_entry_set_text(GTK_ENTRY(params->passwd_entry), "");

            hildon_banner_show_information (GTK_WIDGET (dialog), 
											NULL, _("cer_ib_incorrect"));
            gtk_widget_grab_focus(params->passwd_entry);
            return;
        }
    }

    /* If there is callback, call it */
    if (params->callback != NULL)
    {
        gtk_widget_destroy(GTK_WIDGET(dialog));
        enter_passwd_dialog = NULL;
        params->callback(params->cert_id,
                         params->got_key,
                         passwd,
                         params->user_data);
    }

    if (passwd != NULL) 
		g_free(passwd);
}


GtkWidget* 
create_password_dialog(gpointer window,
					   X509* cert,
					   const gchar* title,
					   const gchar* greeting,
					   const gchar* label,
					   const gchar* ok_label,
					   const gchar* cancel_label,
					   GtkWidget** passwd_entry,
					   gboolean install_timeout,
					   guint min_chars)
{
    GtkWidget* passwd_dialog = NULL;
    gchar* name = NULL;
    GtkWidget* entry_text = NULL;
    GtkWidget* ok_button = NULL;
    GtkWidget* name_label = NULL;
    GtkWidget* passwd_caption = NULL;
    GdkGeometry hints;
    GtkSizeGroup *group = GTK_SIZE_GROUP(
        gtk_size_group_new(GTK_SIZE_GROUP_HORIZONTAL));

    static GtkWidget* params[2];

    /* Construct dialog */
    passwd_dialog = gtk_dialog_new_with_buttons(
        title,
        GTK_WINDOW(window),
        GTK_DIALOG_MODAL
        | GTK_DIALOG_DESTROY_WITH_PARENT
        | GTK_DIALOG_NO_SEPARATOR,
        NULL);

    /* Add buttons to dialog */
    ok_button = gtk_dialog_add_button(GTK_DIALOG(passwd_dialog),
                                      ok_label,
                                      GTK_RESPONSE_OK);

	entry_text = gtk_label_new(greeting);
	gtk_label_set_line_wrap(GTK_LABEL(entry_text), TRUE);
	gtk_container_add(
        GTK_CONTAINER(GTK_DIALOG(passwd_dialog)->vbox),
        entry_text);

    /* Set window geometry */
    hints.min_width  = PASSWD_MIN_WIDTH;
    hints.min_height = PASSWD_MIN_HEIGHT;
    hints.max_width  = PASSWD_MAX_WIDTH;
    hints.max_height = PASSWD_MAX_HEIGHT;

    gtk_window_set_geometry_hints(GTK_WINDOW(passwd_dialog),
                                  passwd_dialog, &hints,
                                  GDK_HINT_MIN_SIZE | GDK_HINT_MAX_SIZE);

    /* If certificate != NULL, then provide "issued to" information */
    if (cert != NULL)
    {
#if 0
        name = get_certificate_name(cert);
        name_label = gtk_label_new(name);
        g_free(name);
#endif
        name = NULL;

        gtk_misc_set_alignment(GTK_MISC(name_label),
                               0.0, 0.5);

        gtk_container_add(
            GTK_CONTAINER(GTK_DIALOG(passwd_dialog)->vbox),
            name_label);
    }

    /* Create new entry and add it to caption control and to
       dialog */
    *passwd_entry = gtk_entry_new();
    hildon_gtk_entry_set_input_mode (GTK_ENTRY (*passwd_entry), 
									 HILDON_GTK_INPUT_MODE_FULL | HILDON_GTK_INPUT_MODE_INVISIBLE);

    passwd_caption = hildon_caption_new(group,
                                        label,
                                        *passwd_entry,
                                        NULL, HILDON_CAPTION_OPTIONAL);

    gtk_container_add(
        GTK_CONTAINER(GTK_DIALOG(passwd_dialog)->vbox),
        passwd_caption);

    /* Connect signal handler */
    if (min_chars > 0)
        g_signal_connect(G_OBJECT(*passwd_entry), "changed",
                         G_CALLBACK(_passwd_text_changed),
                         ok_button);

    /* Set delay and add timeout, if it doesn't exist yet */
    if (timeout_id > 0)
    {
        g_source_remove(timeout_id);
        timeout_id = 0;
    }

    if (install_timeout)
    {
        if (delays[current_delay] < 0) current_delay = 0;
        time_left = delays[current_delay];

        params[0] = *passwd_entry;
        params[1] = ok_button;
        timeout_id = g_timeout_add(1000,
                                   _timeout_handler,
                                   &params);
    }

    /* Disable the OK-button */
    if (min_chars > 0) gtk_widget_set_sensitive(ok_button, FALSE);

    return passwd_dialog;
}


static void _passwd_text_changed(GtkEditable *editable,
                                 gpointer user_data)
{
    GtkWidget* button = GTK_WIDGET(user_data);
    GtkEntry* entry = GTK_ENTRY(editable);
    const gchar* text = NULL;

    /* If entry or button is NULL, bail out */
    if (entry == NULL || button == NULL) return;

    text = gtk_entry_get_text(entry);

    if (strlen(text) > 0 && time_left < 1)
    {
        gtk_widget_set_sensitive(button, TRUE);
    } else {
        gtk_widget_set_sensitive(button, FALSE);
    }
}


static gboolean 
_timeout_handler(gpointer user_data)
{
    /* Get entry text */
    const gchar* text = NULL;

    GtkWidget** params = (GtkWidget**)user_data;
    GtkWidget* passwd_entry;
    GtkWidget* button;

    if (params == NULL)
    {
        return FALSE;
    }

    if (time_left < 0)
    {
        timeout_id = 0;
        return FALSE;
    }

    if (time_left > 0) {
        time_left -= 1;
        return TRUE;
    }

    /* Get params */
    passwd_entry  = params[0];
    button = params[1];

    /* Enable button, if there is text in the entry */
    text = gtk_entry_get_text(GTK_ENTRY(passwd_entry));
    if (strlen(text) > 0)
    {
        gtk_widget_set_sensitive(button, TRUE);
    }

    timeout_id = 0;
    return FALSE;
}
