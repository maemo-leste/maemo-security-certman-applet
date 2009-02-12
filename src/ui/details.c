/* -*- mode:c++; tab-width:4; c-basic-offset:4; -*- */
/**
   @file details.c

   Certificate details dialog.
   <p>
   Copyright (c) 2005 Nokia. All rights reserved.

   @author  Karoliina T. Salminen <karoliina.t.salminen@nokia.com>
*/

#define _BSD_SOURCE
#include <libosso.h>
#include <osso-log.h>
#include <stdio.h>
#include <string.h>
#include <hildon/hildon.h>
#include <gdk/gdkkeysyms.h>
#include <openssl/pem.h>
#include <stdlib.h>
#include <time.h>
#include <maemosec_common.h>

#include <unistd.h>

#include "uidefs.h"
#include "uiutils.h"
#include "i18n.h"
#include "osso-applet-certman.h"

// TODO: Get rid of this
extern osso_context_t *osso_global;

extern char *tzname[2];
extern long timezone;
extern int daylight;

/* Local interface */

typedef enum {
    /** Full details dialog with all other buttons than install */
    DIALOG_FULL,
    /** The most simple details dialog with just Close-button */
    DIALOG_SIMPLE,
    /** The simple details dialog with an install button */
    DIALOG_INSTALL
} DetailsDialogType;




/**
   Creates the certificate details dialog with different parameters.

   @param window        The parent window for the dialog.
   @param type
   @param cert_id
   @param cert

   @return TRUE, if the given certificate was installed. Returns always
   FALSE, if cert_id is specified (and cert is not specified).
*/
static gboolean _certificate_details(gpointer window,
                                     DetailsDialogType type,
                                     X509* cert);


/**
   Creates an infobox for a given certificate.

   @param cert_id       ID for given certificate, or 0, if cert is provided
   @param cert          Certificate, if no cert_id is 0.
*/
static GtkWidget* _create_infobox(X509* cert);

/**
   Adds labels to the given table.
*/
static void _add_labels(GtkTable* table, gint* row,
                        const gchar* label, const gchar* value, gboolean wrap);

/* Implementation */

/* Certificate details */

extern gboolean close_store_on_exit;


gboolean 
certmanui_install_certificate_details_dialog(gpointer window,
											 X509* cert)
{
    return _certificate_details(window, DIALOG_INSTALL, cert);
}


void 
certmanui_certificate_details_dialog(gpointer window,
									 gboolean simple,
									 X509* certificate) 
{
    (void)_certificate_details(window,
                               simple? DIALOG_SIMPLE : DIALOG_FULL,
							   certificate);
}


void 
certmanui_simple_certificate_details_dialog(gpointer window,
											X509* cert)
{
    (void)_certificate_details(window, DIALOG_SIMPLE, cert);
}

static gboolean
return_FALSE(GtkWidget *dialog, GdkEvent *event, gpointer null)
{
  return TRUE;
}

static gboolean 
_certificate_details(gpointer window,
					 DetailsDialogType type,
					 X509* cert)
{
    GtkWidget* cert_dialog = NULL;
    GtkWidget* cert_notebook = NULL;
    GtkWidget* cert_main_page = NULL;
    GtkWidget* cert_chains_page = NULL;
    GtkWidget* cert_passwd_button = NULL;

    GtkWidget* cert_simple_dialog = NULL;
    GtkWidget* current_dialog = NULL;


    GdkGeometry hints;
    GtkWidget* infobox = NULL;
    GtkWidget* scroller = NULL;
    GtkWidget* chain_scroller = NULL;
    GtkRequisition requisition;
    gboolean certificate_installed = FALSE;
    gint ret = 0;
    gboolean simple = TRUE; // (type != DIALOG_FULL);

    if (osso_global == NULL)
    {
        ULOG_CRIT("osso_global is NULL");
        return FALSE;
    }

    /* Check that if dialog is install, then cert structure is supplied, cert_id is not used */
    if (type == DIALOG_INSTALL && cert == NULL) {
        ULOG_CRIT("Install dialog requested, certificate structure is NULL");
        return FALSE;
    }


    /* Check if cert_dialog != NULL */
    if (simple)
    {
		MAEMOSEC_DEBUG(1, "%s: show simple dialog", __func__);
        if (cert_simple_dialog == NULL)
        {
            cert_simple_dialog = gtk_dialog_new_with_buttons(
                _("cert_ti_viewing_dialog"),
                GTK_WINDOW(window),
                GTK_DIALOG_MODAL
                | GTK_DIALOG_DESTROY_WITH_PARENT
                | GTK_DIALOG_NO_SEPARATOR,
                NULL);
            if (cert_simple_dialog == NULL)
            {
                return FALSE;
            }
            /* Add install button, if required */
            if (type == DIALOG_INSTALL &&
                cert_simple_dialog != NULL)
            {
                gtk_dialog_add_button(
                    GTK_DIALOG(cert_simple_dialog),
                    _("cert_bd_cd_install"),
                    CM_RESPONSE_INSTALL);
            }
            /* Add close button */
            if (cert_simple_dialog != NULL)
            {
                gtk_dialog_add_button( GTK_DIALOG (cert_simple_dialog),
                                       _("cert_bd_c_close"),
                                       CM_RESPONSE_CLOSE);
            }
        }

        current_dialog = cert_simple_dialog;

    } else {
		MAEMOSEC_DEBUG(1, "%s: show detailed dialog", __func__);
        if (cert_dialog == NULL)
        {
            cert_dialog = gtk_dialog_new_with_buttons(
                _("cert_ti_viewing_dialog"),
                GTK_WINDOW(window),
                GTK_DIALOG_MODAL
                | GTK_DIALOG_DESTROY_WITH_PARENT
                | GTK_DIALOG_NO_SEPARATOR,
                NULL);

            /* Add buttons to dialog */
            gtk_dialog_add_button(GTK_DIALOG(cert_dialog),
                                  _("cert_bd_c_delete"),
                                  CM_RESPONSE_DELETE);

            cert_passwd_button = gtk_dialog_add_button(
                GTK_DIALOG(cert_dialog),
                _("cert_bd_c_password"),
                CM_RESPONSE_PASSWORD);

            gtk_dialog_add_button(GTK_DIALOG(cert_dialog),
                                  _("cert_bd_c_trust"),
                                  CM_RESPONSE_TRUST);

            gtk_dialog_add_button(GTK_DIALOG(cert_dialog),
                                  _("cert_bd_c_close"),
                                  CM_RESPONSE_CLOSE);

            /* Create dialog pages and notebook */
            cert_main_page = gtk_vbox_new(FALSE, 2);
            cert_chains_page = gtk_vbox_new(FALSE, 2);

            cert_notebook = gtk_notebook_new();

            /* Append pages to notebook */
            gtk_notebook_append_page(
                GTK_NOTEBOOK(cert_notebook),
                cert_main_page, NULL);
            gtk_notebook_set_tab_label_text(
                GTK_NOTEBOOK(cert_notebook),
                cert_main_page,
                _("cert_ti_main"));

            gtk_notebook_append_page(
                GTK_NOTEBOOK(cert_notebook),
                cert_chains_page, NULL);
            gtk_notebook_set_tab_label_text(
                GTK_NOTEBOOK(cert_notebook),
                cert_chains_page,
                _("cert_ti_chains"));

            /* Put notebook to dialog */
            gtk_container_add(
                GTK_CONTAINER(GTK_DIALOG(cert_dialog)->vbox),
                cert_notebook);
        }

        current_dialog = cert_dialog;

        g_signal_connect(G_OBJECT(current_dialog), "delete-event", (GCallback)return_FALSE, NULL);

    }

    infobox = _create_infobox(cert);

    /* Unable to open certificate, give error and exit */
    if (infobox == NULL)
    {
		MAEMOSEC_DEBUG(1, "Failed to create infobox");
        hildon_banner_show_information (window, NULL, _("cert_error_open"));
        if (close_store_on_exit)
        {
            gtk_widget_destroy(current_dialog);
            if (current_dialog == cert_dialog)
            {
                cert_dialog = NULL;
            } else {
                cert_simple_dialog = NULL;
            }
        }
        return FALSE;
    }

    /* Put infobox in a scroller and add that to dialog */
    scroller = create_scroller(infobox);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroller),
                                   GTK_POLICY_AUTOMATIC,
                                   GTK_POLICY_AUTOMATIC);


    /* Put infobox scroller to right place */
    if (simple)
    {
        gtk_container_add(
            GTK_CONTAINER(GTK_DIALOG(current_dialog)->vbox),
            scroller);

    }
	gtk_container_add(GTK_CONTAINER(cert_main_page), scroller);

    /* Set window geometry */
    hints.min_width  = DETAILS_MIN_WIDTH;
    hints.min_height = DETAILS_MIN_HEIGHT;
    hints.max_width  = DETAILS_MAX_WIDTH;
    hints.max_height = DETAILS_MAX_HEIGHT;

    /* "Violently" allocate more width for dialog, if it is needed */
    gtk_widget_show_all(infobox);
    gtk_widget_size_request(infobox, &requisition);
    if (requisition.width + HILDON_MARGIN_DOUBLE * 5 > DETAILS_MIN_WIDTH)
    {
        hints.min_width  = requisition.width + HILDON_MARGIN_DOUBLE * 5;

        if (hints.min_width > hints.max_width)
        {
            hints.max_width = hints.min_width;
        }
    }

    gtk_window_set_geometry_hints(GTK_WINDOW(current_dialog),
                                  current_dialog, &hints,
                                  GDK_HINT_MIN_SIZE | GDK_HINT_MAX_SIZE);

    /* Add context sensitive help icon */
    hildon_help_dialog_help_enable(GTK_DIALOG(current_dialog),
                                CM_HELP_KEY_DETAILS,
                                osso_global);

    /* Show and run the dialog */
	MAEMOSEC_DEBUG(1, "Showing details");
    gtk_widget_show_all(current_dialog);

    if (cert_notebook)
    {
        gtk_widget_grab_focus(cert_notebook);
    }

    while (ret != CM_RESPONSE_CLOSE)
    {
        ULOG_DEBUG("Before gtk_dialog_run\n");
        ret = gtk_dialog_run(GTK_DIALOG(current_dialog));
        ULOG_DEBUG("After gtk_dialog_run\n");

        if (GTK_RESPONSE_DELETE_EVENT == ret) {
			ret = CM_RESPONSE_CLOSE;
        }
    }

    gtk_widget_hide_all(current_dialog);

    /* Scroller is always destroyed */
    gtk_widget_destroy(scroller);
    scroller = NULL; infobox = NULL;

    /* If not simple dialog, destroy chain scroller */
    if (!simple)
    {
        gtk_widget_destroy(chain_scroller); chain_scroller = NULL;
    }

    /* Save store and delete dialog, if they weren't initialized */

    if (current_dialog == cert_dialog) cert_dialog = NULL;
    else cert_simple_dialog = NULL;
    gtk_widget_destroy(current_dialog);

    if (close_store_on_exit)
    {
        if (current_dialog == cert_dialog)
        {
            cert_dialog = NULL;
        } else {
            cert_simple_dialog = NULL;
        }
        gtk_widget_destroy(current_dialog);
    }
    return certificate_installed;
}


static int
get_fingerprint(X509 *of_cert, 
				EVP_MD* of_type, 
				char* label, 
				size_t label_size,
				char* value,
				size_t value_size)
{
	unsigned char digest_bin[64];
	size_t digest_len, i;
	char* digest_name, *hto;

	if (of_type == EVP_sha1()) 
		digest_name = "SHA1";
	else if (of_type == EVP_md5())
		digest_name = "MD5";
	else {
		MAEMOSEC_ERROR("Unknown digest type");
		return(0);
	}
	
	if (X509_digest(of_cert, of_type, digest_bin, &digest_len)) {
		snprintf(label, 
				 label_size,
				 _("cert_fi_certmang_fingerprint"), 
				 digest_name);
		hto = value;
		for (i = 0; i < digest_len; i++) {

			if (3 > value_size)
				goto buffer_overflow;
			sprintf(hto, "%02X", digest_bin[i]);
			value_size -= 2;
			hto += 2;

			/*
			 * Add punctuation to make the hexstring more
			 * readable.
			 */
			if (2*(i + 1) == digest_len) {
				if (2 > value_size)
					goto buffer_overflow;
				*hto++ = '\n';
				value_size--;
				*hto = '\0';

			} else if (i > 0 && (i + 1) < digest_len && (i + 1) % 2 == 0) {
				if (2 > value_size)
					goto buffer_overflow;
				*hto++ = ' ';
				value_size--;
				*hto = '\0';
			}
		}
		return(1);

	} else {
		return(0);
	}

 buffer_overflow:
	MAEMOSEC_ERROR("digest does not fit into given buffer");
	return(0);
}


static void
set_multiline_value(GtkWidget* infobox, gint* row, const char* label, const char* text)
{
	char *nl;

	do {
		nl = strchr(text, '\n');
		if (nl) 
			*nl = '\0';

		_add_labels(GTK_TABLE(infobox),
					row,
					label, 
					text,
					FALSE);
		if (nl) {
			text = nl + 1;
			label = "";
		}
	} while (nl);
}


static int
ASN1_time_to_localtime_str(ASN1_TIME* atime, char* to_buf, const unsigned buf_size)
{
	struct tm r;
	int cnt;
	time_t res;

	ASN1_GENERALIZEDTIME* agtime;

	if (!atime || !atime->data) {
		MAEMOSEC_ERROR("Empty time");
		return(0);
	}
		
	agtime = ASN1_TIME_to_generalizedtime(atime, NULL);

	if (!agtime) {
		MAEMOSEC_ERROR("Invalid time '%s'", atime->data);
		return(0);
	}
	memset(&r, '\0', sizeof(struct tm));
	cnt = sscanf((char*)agtime->data, "%04d%02d%02d%02d%02d%02d",
				 &r.tm_year, &r.tm_mon, &r.tm_mday, 
				 &r.tm_hour, &r.tm_min, &r.tm_sec);
	ASN1_TIME_free(agtime);
	if (cnt < 6) {
		MAEMOSEC_ERROR("Invalid time '%s'", agtime->data);
		return(0);
	}
	MAEMOSEC_DEBUG(1, "%04d-%02d-%02d %02d:%02d:%02d", 
				   r.tm_year, r.tm_mon, r.tm_mday, 
				   r.tm_hour, r.tm_min, r.tm_sec);
	r.tm_mon--;
	r.tm_year -= 1900;
	/*
	 * Unfortunately there is not an easy way to convert UTC time
	 * to time_t, as mktime expects local time. Subtract the
	 * timezone manually.
	 */
	res = mktime(&r);
	if ((time_t)-1 != res) {
		struct tm ltm;
		res -= timezone;
		localtime_r(&res, &ltm);
		strftime(to_buf, buf_size, "%X %x %z", &ltm);
		MAEMOSEC_DEBUG(1, "%s", to_buf);
		return(1);
	}
	return(0);
}


static GtkWidget* 
_create_infobox(X509* cert)
{
    gint row = 0;
    GtkWidget* infobox;

	MAEMOSEC_DEBUG(1, "Enter %s", __func__);
	if (!cert) {
		MAEMOSEC_ERROR("No certificate!");
		return(NULL);
	}

    infobox = gtk_table_new(13, 2, FALSE);

    gtk_table_set_col_spacings(GTK_TABLE(infobox), HILDON_MARGIN_DEFAULT);
    gtk_table_set_row_spacings(GTK_TABLE(infobox), 0);

    /* Populate information area */

    /* Issued to, issued by */
	{
		gchar *issued_to=NULL, *issued_by=NULL;

		issued_to = X509_NAME_to_str(X509_get_subject_name(cert), FALSE);
		_add_labels(GTK_TABLE(infobox),
					&row, 
					_("cert_fi_certmang_issued_to"), 
					issued_to, 
					TRUE);

		issued_by = X509_NAME_to_str(X509_get_issuer_name(cert), FALSE);
		/*
		 * TODO: A more accurate test might be needed
		 */
		if (strcmp(issued_to, issued_by) == 0) {
			_add_labels(GTK_TABLE(infobox),
						&row, 
						_("cert_fi_certmang_issued_by"), 
						"(self-signed)",
						TRUE);
		} else {
			_add_labels(GTK_TABLE(infobox),
						&row, 
						_("cert_fi_certmang_issued_by"), 
						issued_by, 
						TRUE);
		}
		MAEMOSEC_DEBUG(1, "Filled issued to '%s', issued by '%s'",
					   issued_to, issued_by);
		g_free(issued_to);
		g_free(issued_by);
	}

	/*
	 * Validity period
	 */
	{
		char timestamp[40];

		/* Valid from, valid to */
		if (ASN1_time_to_localtime_str(X509_get_notBefore(cert),
									  timestamp,
									  sizeof(timestamp)))
			_add_labels(GTK_TABLE(infobox),
						&row, 
						_("cert_fi_certmang_valid"), 
						timestamp, 
						TRUE);
		if (ASN1_time_to_localtime_str(X509_get_notAfter(cert),
									  timestamp,
									  sizeof(timestamp)))
			_add_labels(GTK_TABLE(infobox),
						&row, 
						_("cert_fi_certmang_valid"), 
						timestamp, 
						TRUE);
	}

    /* Fingerprint */
	{
		char fingerprint_label[100];
		char fingerprint_text [100];

		if (get_fingerprint(cert, 
							EVP_sha1(), 
							fingerprint_label, 
							sizeof(fingerprint_label),
							fingerprint_text,
							sizeof(fingerprint_text)
							)
			)
			set_multiline_value(infobox, &row, fingerprint_label, fingerprint_text);

		if (get_fingerprint(cert, 
							EVP_md5(), 
							fingerprint_label, 
							sizeof(fingerprint_label),
							fingerprint_text,
							sizeof(fingerprint_text)
							)
			)
			set_multiline_value(infobox, &row, fingerprint_label, fingerprint_text);
	}
    return(infobox);
}


static void _add_labels(GtkTable* table, 
						gint* row,
                        const gchar* label, 
						const gchar* value, 
						gboolean wrap)
{
    GtkWidget* label_label;
    GtkWidget* value_label;

    /* Add two labels on a given row */
    label_label = gtk_label_new(label);
    value_label = gtk_label_new(NULL);

    gtk_label_set_markup(GTK_LABEL(value_label), value);
    gtk_table_attach(table, label_label, 0, 1, *row, (*row)+1,
                     (GtkAttachOptions) (GTK_FILL),
                     (GtkAttachOptions) (GTK_FILL), 0, 0);
    gtk_table_attach(table, value_label, 1, 2, *row, (*row)+1,
                     (GtkAttachOptions) (GTK_FILL),
                     (GtkAttachOptions) (0), 0, 0);

    if (wrap)
        gtk_label_set_line_wrap(GTK_LABEL(value_label), TRUE);

    gtk_misc_set_alignment(GTK_MISC(label_label), 1.0, 0.0);
    gtk_misc_set_alignment(GTK_MISC(value_label), 0.0, 0.0);


    *row += 1;
}
