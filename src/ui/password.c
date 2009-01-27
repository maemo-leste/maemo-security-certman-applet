/* -*- mode:c++; tab-width:4; c-basic-offset:4; -*- */
/**
   @file password.c

   Password changing dialog.
   <p>
   Copyright (c) 2005 Nokia. All rights reserved.

   @author  Karoliina T. Salminen <karoliina.t.salminen@nokia.com>
*/

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
    gint key_id;
    maemosec_key_id cert_id;
    X509* cert;
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


gboolean certmanui_change_password(gpointer window, maemosec_key_id cert_id)
{
    maemosec_key_id new_key_id;
    return _change_password(window, cert_id, 0, &new_key_id, NULL);
}




gboolean certmanui_change_privatekey_password(gpointer window,
                                              maemosec_key_id key_id,
                                              maemosec_key_id* new_key_id,
                                              gchar** new_passwd)
{
    /* Is this function ever used even if it is in the API?  Refer
       to long comment in _change_password at (cert_id == 0) */
    maemosec_key_id spare_new_key_id;

    if (new_key_id == NULL)
    {
        return _change_password(window, 0, key_id, &spare_new_key_id,
                                new_passwd);
    }

    return _change_password(window, 0, key_id, new_key_id, new_passwd);
}

static gboolean _change_password(gpointer window, maemosec_key_id cert_id,
                                 maemosec_key_id key_id, maemosec_key_id* new_key_id,
                                 gchar** new_passwd)
{
    GtkWidget* passwd_dialog = NULL;
    GtkWidget* passwd_entry = NULL;

    gchar *old_passwd = NULL,
        *new_passwd1 = NULL;
    gchar *tmp = NULL;
    FILE* fp = NULL;

    EVP_PKEY* private_key = NULL;
    X509* cert = NULL;
    X509_NAME* account = NULL;

    gint response = 0;
    gint ret = 0;

    GSList* list = NULL;
    GSList* listiter = NULL;

    g_return_val_if_fail((cert_id >  0 && key_id == 0) ||
                         (cert_id == 0 && key_id >  0), FALSE);

    /* Get certificate (if it exists) */
    if (cert_id > 0)
    {
        if (cert == NULL) {
            ULOG_ERR("Unable to get certificate #%d", cert_id);
            hildon_banner_show_information (window, NULL, _("cert_error_cert_notfound"));
            return FALSE;
        }
        X509_free(cert); cert = NULL;

        /* Get private key ID from the certificate */
        if (key_id == 0)
        {
            ULOG_ERR("Unable to get key for the certificate #%d",
                     cert_id);
            hildon_banner_show_information(window, NULL, _("cert_error_key_notfound"));
            return FALSE;
        }
    }

    /* Check that the private key realy exists */
    if (private_key == NULL)
    {
        {
            hildon_banner_show_information (window, NULL, _("cert_error_key_notfound"));
            return FALSE;
        }
    }
    else
    {
        /* Password is empty, we could skip the asking of old
           password but because it would need UI changes so
           free the key and ask anyway for the password */
        EVP_PKEY_free(private_key);
        private_key = NULL;
    }

    /* It might be that the original author of this function has
       tought that if this function is called with key_id, then
       the key is not bound to a certificate.  But to make sure we
       will check for a possible certificate.  This function was
       previously used with key_id trough
       certmanui_change_privatekey_password() from
       certmanui_import_private_key_file().  But the private key
       importing was changed so that it does not call these
       functions anymore so it might be that the calling this
       function with key_id is not needed anymore at all */
    if (cert_id == 0)
    {
        /* Get account for the private key */

        /* Try to find the certificate which is assosiated to
           the private key. If none is found assume that it
           was not set and we wont bind the key with any
           certificate after the password has been changed. */
        for(listiter = list; listiter; listiter = listiter->next)
        {
            {
				memcpy(cert_id, listiter->data, sizeof(maemosec_key_id));
                break;
            }
        }
        g_slist_free(list);
        list = NULL;
        listiter = NULL;

        /* Free the account here so we don't need to check for it
           before every return, get it again when it is needed*/
        if (account) { X509_NAME_free(account); account = NULL; }
    }

    while (private_key == NULL) {
        /*-- Phase 1, ask for the old password --*/
        tmp = g_strconcat(_("cert_ti_change_password"), " 1/3", NULL);
        passwd_dialog = create_password_dialog(window, NULL, tmp,
											   "",
                                               _("cert_ia_enter_password"),
                                               _("cert_bd_change_password_ok"),
                                               _("cert_bd_change_password_cancel"),
                                               &passwd_entry,
                                               TRUE, 0);
        g_free(tmp);

        /* Run the dialog */
        gtk_widget_show_all(passwd_dialog);
        response = gtk_dialog_run(GTK_DIALOG(passwd_dialog));

        if (response != GTK_RESPONSE_OK)
        {
            if (timeout_id > 0)
            {
                g_source_remove(timeout_id);
                timeout_id = 0;
            }

            gtk_widget_destroy(passwd_dialog);
            passwd_dialog = NULL; passwd_entry = NULL;
            time_left = -1;
            if (old_passwd != NULL) { g_free(old_passwd); old_passwd = NULL; }
            return FALSE;
        }

        old_passwd = g_strdup(gtk_entry_get_text(
                                  GTK_ENTRY(passwd_entry)));
        gtk_widget_destroy(passwd_dialog); passwd_dialog = NULL;
        time_left = -1;


        /* Try to get the private key by using the old password */
        /* Check if empty string means that there is no password */
        if (private_key == NULL && strcmp(old_passwd, "") == 0)
        {
            if (old_passwd != NULL) { g_free(old_passwd); old_passwd = NULL; }
        }

        /* If we didn't get the private key, then password is incorrect */
        if (private_key == NULL)
        {
            hildon_banner_show_information (window, NULL, _("cer_ib_incorrect"));
            if (old_passwd != NULL) { g_free(old_passwd); old_passwd = NULL; }
            current_delay += 1;
        }

    }

    /* Zero the delay */
    current_delay = 0;

    if (!ask_for_new_password(window, &new_passwd1, TRUE))
    {
        if (old_passwd) { g_free(old_passwd); old_passwd = NULL; }

        /* free private key here */
        return FALSE;
    }

    /* Now we have private_key and key_id, then
       1) Export key from store to a file.
       2) Delete key from store,
       3) Import key with new password and try to get new id
       4) Use new id to assign this key for our certificate */

    /* Open temporary file */
    fp = tmpfile();
    if (fp == NULL)
    {
        ULOG_ERR("Unable to open temporary file.");
        hildon_banner_show_information (window, NULL, _("cert_error_undef"));

        if (old_passwd != NULL) g_free(old_passwd);
        if (new_passwd1 != NULL) g_free(new_passwd1);

        return FALSE;
    }


    /* Write private key to temporary file */
    {
        ULOG_ERR("Unable to write to temporary file.");
        fclose(fp);
        hildon_banner_show_information(window, NULL, _("cert_error_undef"));

        if (old_passwd != NULL) g_free(old_passwd);
        if (new_passwd1 != NULL) g_free(new_passwd1);

        if (private_key) EVP_PKEY_free(private_key);
        return FALSE;
    }

    if (0 != ret)
    {
        fclose(fp);
        ULOG_ERR("Unable to delete key from the storage");
        show_cst_error(GTK_WINDOW(window), ret);

        if (old_passwd != NULL) g_free(old_passwd);
        if (new_passwd1 != NULL) g_free(new_passwd1);
        if (account) { X509_NAME_free(account); account = NULL; }

        return FALSE;
    }

    /* Import key with new password */
    rewind(fp);

    /* Free account */
    if (account) { X509_NAME_free(account); account = NULL; }

    /* Free old password */
    g_free(old_passwd);

    if (*new_key_id == 0)
    {
        ULOG_ERR("Unable to import key back to storage, "
                 "CST Error: %d", ret);
        fclose(fp);

        switch(ret)
        {
        default:
            hildon_banner_show_information (window, NULL, _("cert_error_undef"));
            break;
        }

        g_free(new_passwd1);

        return FALSE;
    }

    /* Close the file  */
    fclose(fp);

    /* Assign private key for the certificate */
    if (cert_id > 0)
    {
        {
            ULOG_ERR("Unable to assign the private key with"
                     "certificate");
            hildon_banner_show_information (window, NULL, _("cert_error_undef"));

            g_free(new_passwd1);
            return FALSE;
        }
    }

    /* Check if new password is needed */
    if (new_passwd == NULL)
    {
        g_free(new_passwd1); new_passwd1 = NULL;
    } else {
        *new_passwd = new_passwd1;
    }

    /* Show infobanner and return success */
    hildon_banner_show_information (window, NULL, _("cert_ib_changed"));

    return TRUE;
}


gboolean ask_for_new_password(gpointer window, gchar** new_passwd1,
                              gboolean old_was_asked)
{
    GtkWidget* passwd_dialog = NULL;
    GtkWidget* passwd_entry = NULL;

    gchar* new_passwd2 = NULL;
    gchar* tmp = NULL;

    gint response = 0;

    while (new_passwd2 == NULL)
    {

        while (*new_passwd1 == NULL)
        {
            /*-- Phase 2, ask for the new password --*/
            tmp = g_strconcat(_("cert_ti_change_password"),
                              old_was_asked?" 2/3":" 1/2",
                              NULL);
            passwd_dialog = create_password_dialog(
                window, NULL, tmp,
				"",
                _("cert_ia_enter_new_password"),
                _("cert_bd_change_password_ok"),
                _("cert_bd_change_password_cancel"),
                &passwd_entry,
                FALSE, 1);
            g_free(tmp);

            /* Run the dialog */
            gtk_widget_show_all(passwd_dialog);
            response = gtk_dialog_run(GTK_DIALOG(passwd_dialog));

            if (response != GTK_RESPONSE_OK)
            {
                if (timeout_id > 0)
                {
                    g_source_remove(timeout_id);
                    timeout_id = 0;
                }

                gtk_widget_destroy(passwd_dialog);
                passwd_dialog = NULL;
                time_left = -1;

                if (*new_passwd1) g_free(*new_passwd1);
                if (new_passwd2) g_free(new_passwd2);

                return FALSE;
            }

            /* Get password and destroy the dialog */
            *new_passwd1 = g_strdup(gtk_entry_get_text(
                                        GTK_ENTRY(passwd_entry)));
            gtk_widget_destroy(passwd_dialog);
            passwd_dialog = NULL;
            time_left = -1;

            /* Check that password has minimum length */
            if (g_utf8_strlen(*new_passwd1, -1) <
                MIN_PASSWD_LENGTH)
            {
                hildon_banner_show_information (window, NULL, _("cert_ib_atleastfive"));

                g_free(*new_passwd1); *new_passwd1 = NULL;
            }
        }

        /*-- Phase 3, verify the new password --*/
        tmp = g_strconcat(_("cert_ti_change_password"),
                          old_was_asked?" 3/3":" 2/2",
                          NULL);
        passwd_dialog = create_password_dialog(window, NULL, tmp,
											   "",
                                               _("cert_ia_verifyn_ew_password"),
                                               _("cert_bd_change_password_ok"),
                                               _("cert_bd_change_password_cancel"),
                                               &passwd_entry,
                                               FALSE, 1);
        g_free(tmp);

        /* Run the dialog */
        gtk_widget_show_all(passwd_dialog);
        response = gtk_dialog_run(GTK_DIALOG(passwd_dialog));

        if (response != GTK_RESPONSE_OK)
        {
            if (timeout_id > 0)
            {
                g_source_remove(timeout_id);
                timeout_id = 0;
            }

            gtk_widget_destroy(passwd_dialog);
            passwd_dialog = NULL;
            time_left = -1;

            if (*new_passwd1 != NULL) g_free(*new_passwd1);
            if (new_passwd2 != NULL) g_free(new_passwd2);

            return FALSE;
        }

        new_passwd2 = g_strdup(gtk_entry_get_text(GTK_ENTRY(passwd_entry)));
        gtk_widget_destroy(passwd_dialog); passwd_dialog = NULL;
        time_left = -1;

        /* Check that passwd1 and passwd2 match. */
        if (strcmp(*new_passwd1, new_passwd2) != 0)
        {
            hildon_banner_show_information (window, NULL, _("cert_ib_needtomatch"));

            g_free(new_passwd2); new_passwd2 = NULL;
            g_free(*new_passwd1); *new_passwd1 = NULL;
        }

    }

    /* We can free the new password duplicate */
    g_free(new_passwd2); new_passwd2 = NULL;
    return TRUE;
}


EVP_PKEY* certmanui_get_privatekey(gpointer window, maemosec_key_id cert_id,
                                   gchar** password,
                                   PrivateKeyResponseFunc callback,
                                   gpointer user_data)
{
    X509* cert = NULL;
    gint response_id = 0;
    gint key_id;
	char key_id_str [MAEMOSEC_KEY_ID_STR_LEN];
	int rc;

    static CallbackParameter params;

	maemosec_certman_key_id_to_str(cert_id, key_id_str, sizeof(key_id_str));
	MAEMOSEC_DEBUG(1, "%s: %s", __func__, key_id_str);

#if 0
	rc = maemosec_certman_load_cert(cert_id, &cert, NULL);

    /* Get certificate for the given ID, and throw error, if not found */
    if (cert == NULL)
    {
        /* Certificate not found banner */
        ULOG_ERR("Unable to get certificate #%s", key_id_str);
        hildon_banner_show_information (window, NULL, _("cert_error_cert_notfound"));
        if (callback != NULL) callback(cert_id, NULL, NULL,
                                       user_data);
        return NULL;
    }

    /* Test that certificate has key */
    if (0 != rc)
    {
        /* Certificate doesn't have a key, give error and return */
        ULOG_ERR("Certificate #%s doesn't have a key", key_id_str);
        hildon_banner_show_information (window, NULL, _("cert_error_key_notfound"));
        if (callback != NULL) callback(cert_id, NULL, NULL,
                                       user_data);
        return NULL;
    }
#endif

    /* Fill in params struct */
    params.got_key = NULL;
    params.key_id = key_id;
    memcpy(params.cert_id, cert_id, sizeof(maemosec_key_id));
    params.cert = cert;
    params.callback = callback;
    params.user_data = user_data;

    /* Create password dialog */
    enter_passwd_dialog = create_password_dialog(window,
                                                 cert,
                                                 _("cert_ti_enter_password"),
												 "",
                                                 _("cert_ia_password"),
                                                 _("cert_bd_enter_password_ok"),
                                                 _("cert_bd_enter_password_cancel"),
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





void certmanui_cancel_privatekey(void)
{
    if (enter_passwd_dialog != NULL)
    {
        gtk_dialog_response(GTK_DIALOG(enter_passwd_dialog),
                            GTK_RESPONSE_CANCEL);
    }
}


static void _password_dialog_response(GtkDialog* dialog,
                                      gint response_id,
                                      gpointer data)
{
    CallbackParameter* params = (CallbackParameter*)data;
    gchar* passwd = NULL;

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

        if (params->got_key != NULL)
        {
            /* Password was correct */

            /* Make duplicate of the key */
            /* params->got_key = EVP_PKEY_dup(params->got_key); */
        } else {
            /* Password was wrong */

            /* Clear entry and show infonote */
            gtk_entry_set_text(GTK_ENTRY(params->passwd_entry),
                               "");

            hildon_banner_show_information (GTK_WIDGET (dialog), NULL, _("cer_ib_incorrect"));
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

    if (passwd != NULL) g_free(passwd);
}


GtkWidget* create_password_dialog(gpointer window,
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

    gtk_dialog_add_button(GTK_DIALOG(passwd_dialog),
                          cancel_label,
                          GTK_RESPONSE_CANCEL);

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


static gboolean _timeout_handler(gpointer user_data)
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
