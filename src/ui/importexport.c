/* -*- mode:c++; tab-width:4; c-basic-offset:4; -*- */
/**
   @file importexport.c

   Importingnd exporting dialogs.
   <p>
   Copyright (c) 2005 Nokia. All rights reserved.

   @author  Karoliina T. Salminen <karoliina.t.salminen@nokia.com>
*/

#define _XOPEN_SOURCE

#include <glib.h>
#include <glib/gstdio.h>

#include <libosso.h>
#include <osso-log.h>
#include <hildon/hildon.h>
#include <hildon/hildon-file-chooser-dialog.h>
#include <gconf/gconf-client.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

#include <unistd.h>
#include <maemosec_common.h>
#include <maemosec_certman.h>

#include "uidefs.h"
#include "uiutils.h"
#include "osso-applet-certman.h"
#include "i18n.h"
#include "password.h"


/*
 * At the time being, have PKCS#12 use purposes 
 * hardcoded
 */


#define MIN_PASS_LENGTH 5

/* Local interface */

gint cc_counter;

typedef enum {
    FORMAT_UNDEFINED, FORMAT_PEM, FORMAT_DER, FORMAT_P12
} FileFormat;

typedef enum {
    FALSE_CALLED, CANCEL_CALLED, OK_CALLED
} CbCalledResult;

typedef enum {
    MMC_NONEXISTING = 0,
    MMC_INTERNAL,
    MMC_EXTERNAL
} MmcSlot;

typedef struct {
    gpointer window;
    gchar* passwd; /* must be freed */
    X509* cert;
    CbCalledResult callback_called;
} PasswordCallbackParameter;

typedef struct {
    gpointer window;
    FileFormat format;
    const gchar* fileuri;
    maemosec_key_id cert_id;
    maemosec_key_id key_id;
    GSList *imported_certs;
    X509 * last_error_cert;
    gboolean error_occured;
    gboolean cancel_pressed;
} ConfirmCallbackParameter;


#define USER_AREA_ENV           "HOME"
#define MMC_AREA_ENV            "MMC_MOUNTPOINT"
#define MMC_AREA_INTERNAL_ENV   "INTERNAL_MMC_MOUNTPOINT"
#define MMC_AREA_FALLBACK       "/media/mmc1"
#define MMC_AREA_INTERNAL_FALLBACK "/media/mmc2"

#define BUFFER_SIZE     8192

/**
   Password callback for the private key password_query

   @param buf           To save password into
   @param size          Size of the buf
   @param rwflag        r/w-flag
   @param u             PasswordCallbackParameter

   @return number of characters in the passphrase
*/
static gint _password_callback(gchar *buf, gint size, gint rwflag, void *u);

/* Import dialog */
GtkWidget* import_dialog = NULL;

#define CST_DISABLE 

gboolean 
certmanui_delete_certificate(gpointer window, maemosec_key_id cert_id)
{
    GtkWidget* cn = NULL;
    X509* certificate = NULL;
    gchar* buf = NULL;
    gchar* name_str = NULL;
    gboolean ret = FALSE;
    gint response;

    MAEMOSEC_DEBUG(1, "Enter %s", __func__);
    /* Get certificate and it's name */
    if (certificate == NULL)
    {
#ifndef CST_DISABLE
        _show_cst_importexport_error(window, CST_ERROR_CERT_NOTFOUND);
#endif
        return FALSE;
    }
#ifndef CST_DISABLE
    name_str = get_certificate_name(certificate);
#endif
    X509_free(certificate);
    certificate = NULL;

    /* Create confirmation note */
    buf = g_strdup_printf(_("cert_nc_confirm_dialog"), name_str);
    g_free(name_str);
    name_str = NULL;

    cn = hildon_note_new_confirmation(GTK_WINDOW(window), buf);
    g_free(buf);
    buf = NULL;
    gtk_widget_show_all(cn);

    /* Run dialog and delete it after running */
    response = gtk_dialog_run(GTK_DIALOG(cn));
    gtk_widget_hide_all(cn);
    gtk_widget_destroy(cn); cn = NULL;

    /* If response was OK, delete certificate */
    if (response == GTK_RESPONSE_OK)
    {
#ifndef CST_DISABLE
        response = CST_delete_cert(get_cst(), cert_id);
#endif
        if (0 != response)
        {
#ifndef CST_DISABLE
            _show_cst_importexport_error(window, response);
#endif
        } else {
            ret = TRUE;
        }
    }

    /* Close store if necessary */
    return ret;
}


static gboolean 
_get_private_key(gpointer window, X509* certificate,
		 EVP_PKEY** pkey, gchar** pk_pwd)
{
    EVP_PKEY *pkey_priv = NULL;
    GtkWidget* passwd_dialog = NULL;
    GtkWidget* pk_pwd_entry = NULL;
    gchar *pk_pwd_priv = NULL;
    gint response = GTK_RESPONSE_OK;
    gboolean ret = FALSE;

    MAEMOSEC_DEBUG(1, "Enter %s", __func__);

    g_return_val_if_fail(GTK_IS_WINDOW(window), FALSE);
    g_return_val_if_fail(pkey, FALSE);
    g_return_val_if_fail(pk_pwd, FALSE);

    /* There's a private key assigned to the
       certificate to be exported */
    /* Get password with which private key
       is stored in the certificate store */

    /* create dialog for querying private key password */
    passwd_dialog = create_password_dialog(window,
                                           certificate,
                                           _("cert_ti_key_password"),
										   "",
                                           _("cert_ia_password"),
                                           dgettext("hildon-libs", "wdgt_bd_done"),
                                           "",
                                           &pk_pwd_entry,
                                           FALSE, 0);

    gtk_widget_show_all(passwd_dialog);

    while (pkey_priv == NULL && response == GTK_RESPONSE_OK) {
        gtk_entry_set_text(GTK_ENTRY(pk_pwd_entry), "");
        gtk_widget_grab_focus(pk_pwd_entry);

        response = gtk_dialog_run(GTK_DIALOG(passwd_dialog));
        if (response == GTK_RESPONSE_OK) {
            g_free(pk_pwd_priv);
            pk_pwd_priv = g_strdup(gtk_entry_get_text(
                                       GTK_ENTRY(pk_pwd_entry)));
#ifndef CST_DISABLE
            pkey_priv = CST_get_priv_key(get_cst(),
                                         certificate, pk_pwd_priv);
#endif
            if (pkey_priv)
            {
                *pkey = pkey_priv;
                *pk_pwd = g_strdup(pk_pwd_priv);
                ret = TRUE;
            }
            {
                hildon_banner_show_information (passwd_dialog,
                              NULL, _("cer_ib_incorrect"));
            }
        }
    }

    gtk_widget_hide_all(passwd_dialog);
    gtk_widget_destroy(passwd_dialog);
    passwd_dialog = NULL;
    g_free(pk_pwd_priv);

    return ret;
}

static int
report_openssl_error(const char* str, size_t len, void* u)
{
	char* tmp = strrchr(str, '\n');
	if (tmp && ((tmp - str) == strlen(str)))
		*tmp = '\0';
	MAEMOSEC_DEBUG(1, "OpenSSL error '%s'", str);
	ERR_clear_error();
	return(0);
}


static const char*
determine_filetype(FILE* fp, void** idata)
{
	X509* cert;
	PKCS12* cont;

	rewind(fp);
	cert = PEM_read_X509(fp, NULL, 0, NULL);
	if (cert) {
		*idata = (void*)cert;
		return("X509-PEM");
	} else
		MAEMOSEC_DEBUG(1, "Not a PEM file");

	rewind(fp);
	cert = d2i_X509_fp(fp, NULL);
	if (cert) {
		*idata = (void*)cert;
		return("X509-DER");
	} else
		MAEMOSEC_DEBUG(1, "Not a DER file");

	rewind(fp);
	cont = d2i_PKCS12_fp(fp, NULL);
	if (cont) {
		*idata = (void*)cont;
		return("PKCS12");
	} else
		MAEMOSEC_DEBUG(1, "Not a PKCS12 file");

	// TODO: Bare key file "evp.h"

	return("Unknown");
}

#define MAX_RETRIES 10

static gchar*
ask_password(gpointer window, int test_password(void* data, gchar* pwd), void* data, gchar* info)
{
	gint response = 0;
	GtkWidget* passwd_dialog = NULL;
	GtkWidget* passwd_entry  = NULL;
	gchar *result, *temp = NULL;
	int retries = 0;

	MAEMOSEC_DEBUG(1, "Ask password");
	passwd_dialog = create_password_dialog(
		window,
		NULL,
		_("cert_ti_enter_file_password"),
		temp = g_strdup_printf(_("cert_ia_explain_file_password"), info),
		_("cert_ia_password"),
		dgettext("hildon-libs", "wdgt_bd_done"),
		"",
		&passwd_entry,
		FALSE, 
		0);

	gtk_widget_show_all(passwd_dialog);
	do {
		response = gtk_dialog_run(GTK_DIALOG(passwd_dialog));
		if (response == GTK_RESPONSE_OK) {
			result = g_strdup(gtk_entry_get_text(GTK_ENTRY(passwd_entry)));
			MAEMOSEC_DEBUG(1, "entered password '%s'", result);
			if (test_password(data, result)) {
				MAEMOSEC_DEBUG(1, "password is OK");
				break;
			} else {
				MAEMOSEC_DEBUG(1, "password is not OK");
				gtk_entry_set_text(GTK_ENTRY(passwd_entry), "");
				hildon_banner_show_information(passwd_dialog, 
											   NULL, 
											   _("cer_ib_incorrect"));
				gtk_widget_grab_focus(passwd_entry);
				g_free(result);
			}
		} else
			result = NULL;
	} while (result && ++retries < MAX_RETRIES);

	if (!result && GTK_RESPONSE_OK == response) {
		MAEMOSEC_ERROR("Failed to enter correct password");
	}

	gtk_widget_hide_all(passwd_dialog);
	gtk_widget_destroy(passwd_dialog);

	if (temp)
		g_free(temp);
	return(result);
}


static gint
ask_domains(gpointer window, 
			GtkWidget **dialog,
			X509 *cert, 
			EVP_PKEY *key, 
			STACK_OF(X509) *ca,
			gchar **user_domain,
			gchar **ca_domain)
{
	GtkWidget *label = NULL;
	GtkWidget *bn_ok = NULL, *bn_cancel = NULL;
	
    GdkGeometry hints;
	gchar *name;
    gint response = 0;
	
	/*
	 * TODO: Use the proper title, not defined currently.
	 */
	*dialog = gtk_dialog_new_with_buttons("Install Certificate",
										 GTK_WINDOW(window),
										 GTK_DIALOG_MODAL
										 | GTK_DIALOG_DESTROY_WITH_PARENT
										 | GTK_DIALOG_NO_SEPARATOR,
										 NULL);

	name = g_strdup_printf(_("cert_ia_explain_trust%s"), "");
	label = gtk_label_new(name);
	g_free(name);
	gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
	gtk_misc_set_alignment(GTK_MISC(label), 0.0, 0.0);
	gtk_container_add(GTK_CONTAINER(GTK_DIALOG(*dialog)->vbox), label);

    bn_ok = gtk_dialog_add_button(GTK_DIALOG(*dialog),
								  dgettext("hildon-libs", "wdgt_bd_done"),
								  GTK_RESPONSE_OK);

	hints.min_width  = PASSWD_MIN_WIDTH;
    hints.min_height = PASSWD_MIN_HEIGHT;
    hints.max_width  = PASSWD_MAX_WIDTH;
    hints.max_height = PASSWD_MAX_HEIGHT;

    gtk_window_set_geometry_hints(GTK_WINDOW(*dialog),
                                  *dialog, &hints,
                                  GDK_HINT_MIN_SIZE | GDK_HINT_MAX_SIZE);

    if (cert != NULL)
    {
		gchar *c = get_certificate_name(cert);
        name = g_strdup_printf("Certificate '%s'", c);
        label = gtk_label_new(name);
        g_free(name);
		g_free(c);
        name = NULL;
        gtk_container_add(
            GTK_CONTAINER(GTK_DIALOG(*dialog)->vbox),
            label);
		gtk_misc_set_alignment(GTK_MISC(label), 0.0, 0.0);
		gtk_misc_set_padding(GTK_MISC(label), 20, 0);
    }

    if (key != NULL)
    {
        label = gtk_label_new("Private key");
        gtk_container_add(
            GTK_CONTAINER(GTK_DIALOG(*dialog)->vbox),
            label);
		gtk_misc_set_alignment(GTK_MISC(label), 0.0, 0.0);
		gtk_misc_set_padding(GTK_MISC(label), 20, 0);
    }

	if (ca) 
    {
		int i;
		for (i = 0; i < sk_X509_num(ca); i++) {
			X509* cacert = sk_X509_value(ca, i);
			gchar* c = get_certificate_name(cacert);
			name = g_strdup_printf("CA Certificate '%s'", c);
			label = gtk_label_new(name);
			g_free(name);
			g_free(c);
			name = NULL;
			gtk_container_add(GTK_CONTAINER(GTK_DIALOG(*dialog)->vbox),
							  label);
			gtk_misc_set_alignment(GTK_MISC(label), 0.0, 0.0);
			gtk_misc_set_padding(GTK_MISC(label), 20, 0);
		}
	}

	label = gtk_label_new(_("cert_ti_application_trust"));
	gtk_container_add(GTK_CONTAINER(GTK_DIALOG(*dialog)->vbox), label);
	gtk_misc_set_alignment(GTK_MISC(label), 0.0, 0.0);
	gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);

	GtkWidget *purpose_list = NULL;
	GtkListStore *lstore = NULL;
    GtkCellRenderer* renderer = NULL;
    GtkTreeViewColumn* column = NULL;
	GtkWidget *scroller = NULL;
	GtkTreeIter iter;
	GtkTreeSelection *sel;

	lstore = gtk_list_store_new(1, G_TYPE_STRING);
	purpose_list = gtk_tree_view_new_with_model(GTK_TREE_MODEL(lstore));

	// What's this?
	// g_object_unref(lstore);

    renderer = gtk_cell_renderer_text_new();
	column = gtk_tree_view_column_new_with_attributes("",
													  renderer,
													  "text",
													  0,
													  NULL);
	gtk_tree_view_column_set_sort_column_id(column, MAIN_NAME_COL);
    gtk_tree_view_column_set_widget(column, NULL);
    gtk_tree_view_append_column(GTK_TREE_VIEW(purpose_list), column);
    scroller = create_scroller_without_viewport(purpose_list);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroller),
                                   GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);

	gtk_container_add(GTK_CONTAINER(GTK_DIALOG(*dialog)->vbox), scroller);

	/*
	 * Add choices
	 */
	int i;
	for (i = 0; NULL != pkcs12_targets[i].symbolic_name; i++) {
		gtk_list_store_append(lstore, &iter);
		gtk_list_store_set(lstore, 
						   &iter, 
						   0, 
						   _(pkcs12_targets[i].symbolic_name),
						   -1);
	}

	sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(purpose_list));
	gtk_tree_selection_set_mode(sel, GTK_SELECTION_SINGLE);
 	// gtk_tree_selection_select_iter(sel, &iter);

    gtk_widget_show_all(*dialog);
    response = gtk_dialog_run(GTK_DIALOG(*dialog));

	if (GTK_RESPONSE_OK == response) {
		if (gtk_tree_selection_get_selected(sel, NULL, &iter)) {
			gchar* desc = NULL;

			MAEMOSEC_DEBUG(1, "something is selected");
			gtk_tree_model_get(GTK_TREE_MODEL(lstore),
							   &iter,
							   0,
							   &desc,
							   -1);
			MAEMOSEC_DEBUG(1, "selected item %s", desc);
			for (i = 0; NULL != pkcs12_targets[i].symbolic_name; i++) {
				if (0 == strcmp(_(pkcs12_targets[i].symbolic_name), desc)) {
					*user_domain = g_strdup(pkcs12_targets[i].user_domain);
					*ca_domain   = g_strdup(pkcs12_targets[i].ca_domain);
					MAEMOSEC_DEBUG(1, "user domain=%s, ca domain=%s (%p/%p)", 
								   *user_domain, *ca_domain, 
								   pkcs12_targets[i].symbolic_name, desc);
					hildon_banner_show_information(*dialog, 
												   NULL, 
												   "Installing certificate");
					break;
				}
			}
			if (desc)
				g_free(desc);
		} else {
			MAEMOSEC_DEBUG(1, "nothing was selected");
			response = GTK_RESPONSE_CANCEL;
			hildon_banner_show_information(*dialog, 
										   NULL, 
										   "No target was selected, cancel");
		}
	} else {
		hildon_banner_show_information(*dialog, 
									   NULL, 
									   "Operation cancelled");
	}

    gtk_widget_set_sensitive(bn_ok, FALSE);
	return(response);
}


/*
 * Check out how much info can be shown about a PKCS12
 * container without giving the actual password. Code
 * borrowed from openssl crypto/pkcs12/p12_kiss.c
 */
static void 
show_pkcs7_info(STACK_OF(PKCS12_SAFEBAG) *bags)
{
	PKCS12_SAFEBAG* bag;
	X509_ATTRIBUTE* attrib;
	int i, j;

	if (!bags) {
		MAEMOSEC_ERROR("cannot decode PKCS7 container");
		return;
	}
	MAEMOSEC_DEBUG(2, "    %d safebags", sk_PKCS12_SAFEBAG_num(bags));
	for (i = 0; i < sk_PKCS12_SAFEBAG_num(bags); i++) {
		bag = sk_PKCS12_SAFEBAG_value(bags, i);
		if (bag) {
			char buf[64];
			const char* bagtype = "";
			switch(M_PKCS12_bag_type(bag)) {
				case NID_pkcs8ShroudedKeyBag:
					bagtype = "PKCS#8 Shrouded Keybag";
					break;
				case NID_certBag:
					bagtype = "Certificate";
					break;
			    default:
					sprintf(buf, "bagtype NID %d", M_PKCS12_bag_type(bag));
					bagtype = (const char*)buf;
			}
			MAEMOSEC_DEBUG(2, "      bag #%d '%s' type %s", i, 
						   PKCS12_get_friendlyname(bag),
						   bagtype);
			if (bag->attrib) {
				for (j = 0; j < sk_X509_ATTRIBUTE_num(bag->attrib); j++) {
					attrib = sk_X509_ATTRIBUTE_value(bag->attrib, j);
					if (attrib) 
						MAEMOSEC_DEBUG(2, "        attrib %d: NID %d", j, 
									   OBJ_obj2nid(attrib->object));
				}
			}
		}
	}
	sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
}


static int
test_pkcs12_password(void* on_data, gchar* password)
{
	PKCS12* data = (PKCS12*) on_data;
	
	if (data) {
		if (password) {
			if (PKCS12_verify_mac(data, password, strlen(password))) {
				MAEMOSEC_DEBUG(1, "'%s' is the correct password", password);
				return(1);
			} else {
				MAEMOSEC_DEBUG(1, "'%s' is not the correct password", password);
			}
		} else if (PKCS12_verify_mac(data, NULL, 0)) {
			MAEMOSEC_DEBUG(1, "NULL is the correct password");
			return(1);
		} else {
			MAEMOSEC_DEBUG(1, "NULL is not the correct password");
			return(0);
		}
	} else {
		MAEMOSEC_DEBUG(1, "No data!");
	}
	return(0);
}


static void
show_pkcs12_info(PKCS12* data)
{
	STACK_OF(PKCS7) *asafes;
	PKCS7 *p7;
	int i, bagnid;

	asafes = PKCS12_unpack_authsafes(data);
	if (!asafes) {
		MAEMOSEC_ERROR("PKCS12_unpack_authsafes returned NULL");
		return;
	}

	MAEMOSEC_DEBUG(2, "%d asafes", sk_PKCS7_num(asafes));
	for (i = 0; i < sk_PKCS7_num(asafes); i++) {
		p7 = sk_PKCS7_value(asafes, i);
		bagnid = OBJ_obj2nid(p7->type);
		switch (bagnid)	{
			case NID_pkcs7_data:
				MAEMOSEC_DEBUG(2, "  %d: PKCS#7 data", i);
				show_pkcs7_info(PKCS12_unpack_p7data(p7));
				break;
			case NID_pkcs7_encrypted:
				MAEMOSEC_DEBUG(2, "  %d: PKCS#7 encrypted data", i);
				show_pkcs7_info(PKCS12_unpack_p7encdata(p7, "wifi", 4));
				break;
			default:
				MAEMOSEC_DEBUG(2, "  %d: NID %d", i, bagnid);
				break;
		}
	}

	sk_PKCS7_pop_free(asafes, PKCS7_free);
}


static gboolean
close_import_dialog(gpointer* the_dialog)
{
	MAEMOSEC_DEBUG(1, "Entered %s", __func__);
	gtk_widget_hide_all((GtkWidget*)the_dialog);
	gtk_widget_destroy(GTK_WIDGET(the_dialog));
	return(FALSE);
}


gboolean 
certmanui_import_file(gpointer window, const gchar* fileuri,
		      maemosec_key_id* cert_id, GSList **pk12_list)
{
    cc_counter = 1;
    ConfirmCallbackParameter param;
    FILE *fp = NULL;
    maemosec_key_id store_cert_id;
	gchar *user_domain = NULL, *ca_domain = NULL;

	ERR_print_errors_cb(report_openssl_error, NULL);

    memset(&param, 0, sizeof(param));

    /* 
	 * Transfer the certificate from URI to tmpfile
	 * URI is of form "file://<absolute-path>" at least in requests
	 * coming from the filemanager.
	 * Gnome VFS was used to convert those, but this is a quick-and-dirty
	 * hack to make the demo day without VFS.
	 */

#define FILEPREFIX "file://"	

    if (strlen(fileuri) > strlen(FILEPREFIX) 
		&& 0 == memcmp(fileuri, FILEPREFIX, strlen(FILEPREFIX)))
    {
		fp = fopen(fileuri + strlen(FILEPREFIX), "rb");
		if (!fp) {
			MAEMOSEC_ERROR("Cannot open '%s'", fileuri);
			return(FALSE);
		}
    } else {
		MAEMOSEC_ERROR("Unsupported protocol in '%s'", fileuri);
		return(FALSE);
	}

	{
		void* idata;
		const char* filetype = determine_filetype(fp, &idata);
		MAEMOSEC_DEBUG(1, "'%s' seems to be '%s'", fileuri, filetype);

		if (strcmp(filetype, "PKCS12") == 0) {
			EVP_PKEY *pkey = NULL;
			X509 *cert = NULL;
			STACK_OF(X509) *ca = NULL;
			gchar* password;
			int rc;
			
			MAEMOSEC_DEBUG(1, "try to parse PKCS12");
			show_pkcs12_info((PKCS12*)idata);

			if (test_pkcs12_password(idata, NULL))
				password = NULL;
			else if (test_pkcs12_password(idata, ""))
				password = "";
			else
				password = ask_password(window, test_pkcs12_password, idata, 
										bare_file_name(fileuri));

			rc = PKCS12_parse((PKCS12*)idata, password, &pkey, &cert, &ca);
			MAEMOSEC_DEBUG(1, "parse PKCS12 returned %d, key=%p, cert=%p, cas=%p", 
						   rc, pkey, cert, ca);

			if (rc) {
				GtkWidget* dialog = NULL;
				domain_handle cdom;
				maemosec_key_id key_id;
				int mrc;

				rc = ask_domains(window, &dialog, cert, pkey, ca, &user_domain, &ca_domain);
				if (NULL == dialog)
					goto certmanui_import_file_cleanup;

				if (GTK_RESPONSE_OK == rc) {

					/*
					 * TODO: Install to several domains
					 */

					if (cert) {
						if (user_domain) {
							mrc = maemosec_certman_open_domain
								(user_domain,
								 MAEMOSEC_CERTMAN_DOMAIN_PRIVATE,
								 &cdom);
							if (0 == mrc) {
								maemosec_certman_add_cert(cdom, cert);
								maemosec_certman_close_domain(cdom);
							}
						}
						maemosec_certman_get_key_id(cert, key_id);
						X509_free(cert);
						cert = NULL;
					}
				
					if (ca) {
						if (ca_domain) {
							mrc = maemosec_certman_open_domain
								(
								 ca_domain, 
								 MAEMOSEC_CERTMAN_DOMAIN_PRIVATE,
								 &cdom);
							if (0 == mrc) {
								int i;
								for (i = 0; i < sk_X509_num(ca); i++) {
									X509* cacert = sk_X509_value(ca, i);
									maemosec_certman_add_cert(cdom, cacert);
								}
								maemosec_certman_close_domain(cdom);
							}
						}
						sk_X509_free(ca);
						ca = NULL;
					}

					if (pkey) {
						maemosec_certman_store_key(key_id, pkey, password);
						EVP_PKEY_free(pkey);
					}

					MAEMOSEC_DEBUG(1, "Certificates installed OK");
					hildon_banner_show_information (dialog,
													NULL, 
													"Certificates installed");
				} else {
					hildon_banner_show_information (dialog,
													NULL, 
													"Installation cancelled");
				}
				/*
				 * Close the dialog in two seconds
				 */
				{
					guint rc = gtk_timeout_add(2000, close_import_dialog, dialog);
					MAEMOSEC_DEBUG(1, "gtk_timeout_add ret %d", rc);
				}
				gtk_dialog_run(GTK_DIALOG(dialog));
			}

			// TODO: Error from invalid PKCS#12 file
		} else if (   0 == strcmp(filetype, "X509-PEM")
				   || 0 == strcmp(filetype, "X509-DER")) 
		{

			GtkWidget* dialog = NULL;
			domain_handle cdom;
			int rc;
			X509 *cert = (X509*) idata;
			rc = ask_domains(window, &dialog, cert, NULL, NULL, &user_domain, &ca_domain);
			if (NULL == dialog)
				goto certmanui_import_file_cleanup;

			if (GTK_RESPONSE_OK == rc) {
				
				rc = maemosec_certman_open_domain
					(user_domain,
					 MAEMOSEC_CERTMAN_DOMAIN_PRIVATE,
					 &cdom);
				if (0 == rc) {
					maemosec_certman_add_cert(cdom, cert);
					maemosec_certman_close_domain(cdom);
					MAEMOSEC_DEBUG(1, "Certificates installed OK");
					hildon_banner_show_information (dialog,
													NULL, 
													"Certificates installed");
				} else {
					hildon_banner_show_information (dialog,
													NULL, 
													"Installation cancelled");
				}
				/*
				 * Close the dialog in two seconds
				 */
				rc = gtk_timeout_add(2000, close_import_dialog, dialog);
				gtk_dialog_run(GTK_DIALOG(dialog));
				X509_free(cert);
				cert = NULL;
			}
		}
	}

 certmanui_import_file_cleanup:

	if (user_domain)
		g_free(user_domain);
	if (ca_domain)
		g_free(ca_domain);
		
	return(TRUE);
}


static gint 
_password_callback(gchar *buf, gint size, gint rwflag, void *u)
{
    gsize str_size = 0;
    gint response = 0;
    GtkWidget* dialog = NULL;
    GtkWidget* entry = NULL;
    PasswordCallbackParameter* param = (PasswordCallbackParameter*)u;

    MAEMOSEC_DEBUG(1, "Enter %s", __func__);

    if (param == NULL)
    {
        ULOG_ERR("_password_callback: Wrong parameters");
        return 0;
    }

    param->callback_called = OK_CALLED;

    dialog = create_password_dialog(param->window,
                                    param->cert,
                                    _("cert_ti_enter_password"),
									"",
                                    _("cert_ia_password"),
                                    "OK", // [wdgt_bd_done]
                                    "",
                                    &entry,
                                    FALSE, 0);

    gtk_widget_show_all(dialog);
    response = gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_hide_all(dialog);

    if (response == GTK_RESPONSE_OK)
    {
        /* Copy from entry to buffer */
        param->passwd =
            g_strdup(gtk_entry_get_text(GTK_ENTRY(entry)));
        str_size = g_strlcpy(buf, param->passwd, size);
    } else {
        /* Cancel calling the callback */
        param->callback_called = CANCEL_CALLED;
    }

    gtk_widget_destroy(dialog);

    return (int)str_size;
}
