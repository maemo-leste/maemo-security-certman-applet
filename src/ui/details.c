/* -*- mode:c++; tab-width:4; c-basic-offset:4; -*- */
/**
   @file details.c

   Certificate details dialog.
   <p>
   Copyright (c) 2005 Nokia. All rights reserved.

   @author  Karoliina T. Salminen <karoliina.t.salminen@nokia.com>
*/

#define _BSD_SOURCE
#define _XOPEN_SOURCE
#include <libosso.h>
#include <osso-log.h>
#include <stdio.h>
#include <ctype.h>
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
                                     int domain_flags,
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
gboolean
certmanui_certificate_details_dialog(gpointer window,
									 int domain_flags,
									 X509* certificate) 
{
    return(_certificate_details(window,
								domain_flags,
								certificate));
}


static gboolean 
_certificate_details(gpointer window,
					 int domain_flags,
					 X509* cert)
{
    GtkWidget* cert_dialog = NULL;
    GtkWidget* cert_notebook = NULL;
    GtkWidget* cert_main_page = NULL;
	GtkWidget *bn_delete = NULL;

    GdkGeometry hints;
    GtkWidget* infobox = NULL;
    GtkWidget* scroller = NULL;
    GtkRequisition requisition;
    gboolean certificate_deleted = FALSE;
    gint ret = 0;

    if (osso_global == NULL)
    {
        MAEMOSEC_ERROR("osso_global is NULL");
        return FALSE;
    }

    /* Check if cert_dialog != NULL */
	MAEMOSEC_DEBUG(1, "%s: show simple dialog", __func__);

	if (cert_dialog == NULL) {
		cert_dialog = gtk_dialog_new_with_buttons
			(_("cert_ti_viewing_dialog"),
			 GTK_WINDOW(window),
			 GTK_DIALOG_MODAL
			 | GTK_DIALOG_DESTROY_WITH_PARENT
			 | GTK_DIALOG_NO_SEPARATOR,
			 NULL);

		if (cert_dialog == NULL) {
			MAEMOSEC_ERROR("Failed to create dialog");
			return FALSE;
		}

	}

    infobox = _create_infobox(cert);

    /* Unable to open certificate, give error and exit */
    if (infobox == NULL)
    {
		MAEMOSEC_DEBUG(1, "Failed to create infobox");
        hildon_banner_show_information (window, NULL, _("cert_error_open"));
		gtk_widget_destroy(cert_dialog);
        return FALSE;
    }

    /* Put infobox in a scroller and add that to dialog */
    scroller = create_scroller(infobox);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroller),
                                   GTK_POLICY_AUTOMATIC,
                                   GTK_POLICY_AUTOMATIC);


    /* Put infobox scroller to right place */
	gtk_container_add(GTK_CONTAINER(GTK_DIALOG(cert_dialog)->vbox),
					  scroller);

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

    gtk_window_set_geometry_hints(GTK_WINDOW(cert_dialog),
                                  cert_dialog, &hints,
                                  GDK_HINT_MIN_SIZE | GDK_HINT_MAX_SIZE);

	if (MAEMOSEC_CERTMAN_DOMAIN_PRIVATE == domain_flags)
		bn_delete = gtk_dialog_add_button(GTK_DIALOG(cert_dialog),
										  _("cert_bd_c_delete"), 
										  GTK_RESPONSE_APPLY);

    /* Show and run the dialog */
	MAEMOSEC_DEBUG(1, "Showing details");
    gtk_widget_show_all(cert_dialog);

    if (cert_notebook)
    {
        gtk_widget_grab_focus(cert_notebook);
    }

    while (ret != GTK_RESPONSE_DELETE_EVENT)
    {
        ULOG_DEBUG("Before gtk_dialog_run\n");
        ret = gtk_dialog_run(GTK_DIALOG(cert_dialog));
        ULOG_DEBUG("After gtk_dialog_run\n");

        if (GTK_RESPONSE_APPLY == ret) {
			/*
			 * Delete certificate
			 */
			MAEMOSEC_DEBUG(1, "%s: Delete!", __func__);
			certificate_deleted = TRUE;
			ret = GTK_RESPONSE_DELETE_EVENT;
        }
    }

    gtk_widget_hide_all(cert_dialog);

    /* Scroller is always destroyed */
    gtk_widget_destroy(scroller);
    scroller = NULL; 
	/* TODO: Infobox needs not to be destroyed? */
	infobox = NULL;

    /* Save store and delete dialog, if they weren't initialized */

	gtk_widget_destroy(cert_dialog);
	if (bn_delete)
		gtk_widget_destroy(bn_delete);
    return(certificate_deleted);
}

gboolean 
certmanui_install_certificate_details_dialog(gpointer window,
											 X509* cert)
{
	MAEMOSEC_DEBUG(1, "Called certmanui_install_certificate_details_dialog");
	_certificate_details(window, 
						 MAEMOSEC_CERTMAN_DOMAIN_SHARED,
						 cert);
	return(FALSE);
}


static int
get_fingerprint(X509 *of_cert, 
				EVP_MD** use_type, 
				char* label, 
				size_t label_size,
				char* value,
				size_t value_size)
{
	EVP_MD* of_type;
	unsigned char digest_bin[64];
	size_t digest_len, i;
	char* digest_name, *hto;

	/*
	 * DEBUG: Warn about MD5-based signatures
	 */
	if (of_cert && of_cert->sig_alg && of_cert->sig_alg->algorithm) {
		i2t_ASN1_OBJECT((char*)digest_bin, 
						sizeof(digest_bin), 
						of_cert->sig_alg->algorithm);
		digest_bin[sizeof(digest_bin)-1] = '\0';
		MAEMOSEC_DEBUG(1, "signed by %s", digest_bin);
		for (hto = digest_bin; *hto; hto++)
			*hto = toupper(*hto);
	} else {
		MAEMOSEC_ERROR("Unknown signature algorithm");
		return(0);
	}

	if (0 == memcmp("MD5", digest_bin, strlen("MD5"))) {
		of_type = EVP_md5();
		digest_name = "MD5";
	} else if (0 == memcmp("MD2", digest_bin, strlen("MD2"))) {
		of_type = EVP_md2();
		digest_name = "MD2";
	} else {
		/*
		 * TODO: What about sha256/384/512 and other more
		 * secure hashes?
		 */
		of_type = EVP_sha1();
		digest_name = "SHA1";
	}
	MAEMOSEC_DEBUG(1, "Compute %s fingerprint", digest_name);
	*use_type = of_type;

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


static const int fullname_components [] = {
		NID_commonName, NID_organizationalUnitName, NID_organizationName
};

struct cb_info {
	GtkWidget* infobox;
	gint* row;
	char* label;
};

static void add_name_component(unsigned char* text, void* ctx)
{
	struct cb_info* lctx = (struct cb_info*)ctx;

	/*
	 * Do not add empty components.
	 */
	if (NULL != text && strlen((char*)text) && NULL != ctx) {
		_add_labels(GTK_TABLE(lctx->infobox),
					lctx->row,
					lctx->label, 
					(char*)text,
					FALSE);
		if ('\0' != *lctx->label)
			*lctx->label = '\0';
	}
}

static void
add_full_name(GtkWidget* infobox, gint* row, const char* label, X509_NAME* from_name)
{
	struct cb_info cbi;

	cbi.infobox = infobox;
	cbi.row = row;
	cbi.label = g_strdup(label);

	pick_name_components_by_NIDS
		(from_name, 
		 fullname_components,
		 sizeof(fullname_components)/sizeof(fullname_components[0]),
		 add_name_component,
		 &cbi);

	g_free(cbi.label);
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
		const char* format;
		res -= timezone;
		localtime_r(&res, &ltm);
		format = dgettext("hildon-libs", "wdgt_va_date_long");
		strftime(to_buf, buf_size, format, &ltm);
		MAEMOSEC_DEBUG(1, "%s", to_buf);
		return(1);
	}
	return(0);
}


static void
check_certificate(X509 *cert, int *self_signed, int *openssl_error)
{
	X509_STORE* tmp_store;
	X509_STORE_CTX *csc;
	int rc;

	*self_signed = 0;
	*openssl_error = 0;
	tmp_store = X509_STORE_new();
	X509_STORE_add_cert(tmp_store, cert);
	
	csc = X509_STORE_CTX_new();
	rc = X509_STORE_CTX_init(csc, tmp_store, cert, NULL);
	
	if (X509_verify_cert(csc) > 0) {
		*self_signed = 1;
	} else {
		*openssl_error = csc->error;
		MAEMOSEC_DEBUG(1, "Verification fails: %s", 
					   X509_verify_cert_error_string(csc->error));
	}
	X509_STORE_CTX_free(csc);
	X509_STORE_free(tmp_store);
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
		int is_self_signed, openssl_error;

		add_full_name(infobox, 
					  &row, 
					  _("cert_fi_certmang_issued_to"), 
					  X509_get_subject_name(cert));
					  
		check_certificate(cert, &is_self_signed, &openssl_error);
		if (is_self_signed) {
			_add_labels(GTK_TABLE(infobox),
						&row, 
						_("cert_fi_certmang_issued_by"), 
						_("cert_fi_certmang_self_signed"),
						TRUE);
		} else {
			add_full_name(infobox, 
						  &row, 
						  _("cert_fi_certmang_issued_by"), 
						  X509_get_issuer_name(cert));
		}
		/*
		 * TODO: Handle openssl error
		 */
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
						_("cert_fi_certmang_expired"), 
						timestamp, 
						TRUE);
	}

    /* Fingerprint */
	{
		EVP_MD* sigtype;
		char fingerprint_label[100];
		char fingerprint_text [100];

		if (get_fingerprint(cert, 
							&sigtype,
							fingerprint_label, 
							sizeof(fingerprint_label),
							fingerprint_text,
							sizeof(fingerprint_text)
							))
		{
			if (EVP_md5() == sigtype || EVP_md2() == sigtype)
				hildon_helper_set_logical_color (GTK_WIDGET(infobox), 
												 GTK_RC_FG, 
												 GTK_STATE_NORMAL, 
												 "AttentionColor");
			set_multiline_value(infobox, &row, fingerprint_label, fingerprint_text);
		}
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
