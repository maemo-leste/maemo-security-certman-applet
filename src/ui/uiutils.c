/* -*- mode:c++; tab-width:4; c-basic-offset:4; -*- */

/**
   @file uiutils.c

   Some useful UI-utils for Certificate Manager.
   <p>
   Copyright (c) 2005 Nokia. All rights reserved.

   @author  Karoliina T. Salminen <karoliina.t.salminen@nokia.com>
*/

#include <hildon/hildon.h>
#include <osso-log.h>

#include <gdk/gdkx.h>
#include "i18n.h"

#include "uiutils.h"
#include "uidefs.h"

/*
 * Mapping to purposes from domain names
 */
const struct pkcs12_target pkcs12_targets [] = {
	{
		.symbolic_name = "cert_nc_purpose_wlan_eap", 
		.user_domain = "wifi-user", 
		.ca_domain = "wifi-ca"
	},
	{
		.symbolic_name = "cert_nc_purpose_ssl_tls", 
		.user_domain = "ssl-user", 
		.ca_domain = "ssl-ca"
	},
	{
		.symbolic_name = "cert_nc_purpose_email_smime", 
		.user_domain = "smime-user", 
		.ca_domain = "smime-ca"
	},
	{
		.symbolic_name = "cert_nc_purpose_software_signing", 
		.user_domain = "ssign-user", 
		.ca_domain = "ssign-ca"
	},
	// End mark
	{
		.symbolic_name = NULL,
		.user_domain = NULL,
		.ca_domain = NULL
	}
};


/* Local interface */

/**
   Gets a pixbuf corresponding a given icon name (in theme)

   @param icon_name Name of the icon.
   @return pixbuf representing the icon.
*/
static GdkPixbuf* _get_icon(gchar* icon_name);

osso_context_t *osso_global = NULL;

/* Implementation */

GdkPixbuf* pixbuf_valid = NULL;
GdkPixbuf* pixbuf_notvalid = NULL;
GdkPixbuf* pixbuf_expired = NULL;

GtkWidget* create_scroller(GtkWidget* child)
{
    GtkAdjustment *hadjustment = NULL, *vadjustment = NULL;
    GtkWidget* viewport = NULL;
    GtkWidget* scroller = NULL;

    if (child == NULL) {
        return NULL;
    }
    /* Create scroller and get adjustments */
    scroller = gtk_scrolled_window_new(NULL, NULL);
    hadjustment = gtk_scrolled_window_get_hadjustment(
        GTK_SCROLLED_WINDOW(scroller));
    vadjustment = gtk_scrolled_window_get_vadjustment(
        GTK_SCROLLED_WINDOW(scroller));

    /* Create viewport and fix it's shadow */
    viewport = gtk_viewport_new(hadjustment, vadjustment);
    gtk_container_add(GTK_CONTAINER(viewport), child);
    gtk_container_set_border_width(GTK_CONTAINER(viewport), 0);
    gtk_viewport_set_shadow_type(GTK_VIEWPORT(viewport),
                                 GTK_SHADOW_NONE);

    /* Set scroller window shadow to NONE */
    gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(scroller),
                                        GTK_SHADOW_NONE);

    /* Add viewport */
    gtk_container_add(GTK_CONTAINER(scroller), viewport);
    gtk_container_set_border_width(GTK_CONTAINER(scroller), 0);

    return scroller;
}


/* see Bugzilla 18749 */
GtkWidget* create_scroller_without_viewport(GtkWidget* child)
{
    GtkAdjustment *hadjustment, *vadjustment;
    GtkWidget* scroller;

    if (child == NULL) {
        return NULL;
    }
    /* Create scroller and get adjustments */
    scroller = gtk_scrolled_window_new(NULL, NULL);
    hadjustment = gtk_scrolled_window_get_hadjustment(
        GTK_SCROLLED_WINDOW(scroller));
    vadjustment = gtk_scrolled_window_get_vadjustment(
        GTK_SCROLLED_WINDOW(scroller));

    /* Set scroller window shadow to NONE */
    gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(scroller),
                                        GTK_SHADOW_NONE);

    /* Add viewport */
    gtk_container_add(GTK_CONTAINER(scroller), child);
    gtk_container_set_border_width(GTK_CONTAINER(scroller), 0);

    return scroller;
}


static GdkPixbuf* _get_icon(gchar* icon_name)
{
    GdkPixbuf* buf = NULL;
    GtkIconTheme* icon_theme = NULL;
    GError* error = NULL;

    icon_theme = gtk_icon_theme_get_default ();

    buf = gtk_icon_theme_load_icon(icon_theme,
                                   icon_name,
                                   ICONSIZE, GTK_ICON_LOOKUP_NO_SVG,
                                   &error);
    if (error != NULL)
    {
        ULOG_ERR("error loading pixbuf: %s", error->message);
        g_error_free(error); error = NULL;

        hildon_banner_show_information (NULL, NULL, _("cert_error_undef"));
        return NULL;
    }

    return buf;
}


GdkPixbuf* get_cert_pixbuf(X509* certificate, gboolean* valid)
{
    /* Get pixbuf according to a certificate state */
    if (1)
    {
        if (pixbuf_valid == NULL)
        {
            pixbuf_valid = _get_icon(CERT_VALID_PIXMAP);
        }

        if (valid != NULL) *valid = TRUE;

        return pixbuf_valid;
    }

    if (pixbuf_notvalid == NULL)
    {
        pixbuf_notvalid = _get_icon(CERT_INVALID_PIXMAP);
    }

    if (valid != NULL) *valid = FALSE;

    return pixbuf_notvalid;
}

void release_pixbufs(void)
{
    if (pixbuf_valid != NULL)
    {
        g_object_unref(pixbuf_valid); pixbuf_valid = NULL;
    }

    if (pixbuf_notvalid != NULL)
    {
        g_object_unref(pixbuf_notvalid); pixbuf_notvalid = NULL;
    }

    if (pixbuf_expired != NULL)
    {
        g_object_unref(pixbuf_expired); pixbuf_expired = NULL;
    }

    return;
}


void show_error_msg(GtkWindow* window, const gchar* msg, gboolean infonote)
{
    GtkWidget* note = NULL;

    g_return_if_fail(window == NULL || GTK_IS_WINDOW(window));
    g_return_if_fail(msg != NULL);

    if (infonote)
    {
        /* Show infonote */
        note = hildon_note_new_information(GTK_WINDOW(window), msg);
        gtk_widget_show_all(note);
        gtk_dialog_run(GTK_DIALOG(note));
        gtk_widget_destroy(note);
    } else  {
        /* Passing NULL to hildon_banner_show_information would not work
           in cases where we are started using an RPC call, we need
           to use osso_system_note_infoprint. But fall back to
           hildon_banner_show_information if we don't have osso_global */
        if (window != NULL || !osso_global)
        {
            hildon_banner_show_information(GTK_WIDGET(window), NULL, msg);
        }
        else
        {
            osso_system_note_infoprint(osso_global, msg, NULL);
        }
    }
}

#define CONCAT_STR ", "
#define PASSWORD NULL
#define INT_BUFSIZE 512
#define DEFAULT_NAME ""

gchar* X509_NAME_to_str(X509_NAME* name, gboolean longform)
{
    X509_NAME_ENTRY* entry = NULL;
    ASN1_STRING* str = NULL;
    gint idx = -1;
    guchar *cn = NULL, *ou = NULL, *o = NULL, *c = NULL, *quark = NULL,
        *cn_alt = NULL, *tmp = NULL;
    static gchar result[INT_BUFSIZE];

    /* Get all common name fields and concatenate */
    for (;;) {
        idx = X509_NAME_get_index_by_NID(name, NID_commonName, idx);
        if (idx == -1)
            break; /* Common name not found */

        entry = X509_NAME_get_entry(name, idx);
        str = X509_NAME_ENTRY_get_data(entry);
        ASN1_STRING_to_UTF8(&quark, str);

        if (quark != NULL)
        {
            if (cn == NULL)
            {
                cn = g_strdup(quark);
            } else {
                tmp = g_strconcat(cn, CONCAT_STR, quark,
                                  NULL);
                g_free(cn);
                cn = tmp;
                tmp = NULL;
            }
        }

        if (quark != NULL) OPENSSL_free(quark);
    }

    /* If there is no Common name, we must form alternate name from
       organizational unit, organization and country */
    if (cn == NULL || longform == TRUE)
    {
        /* Get organizational unit name */
        idx = X509_NAME_get_index_by_NID(name,
                                         NID_organizationalUnitName,
                                         -1);
        if (idx != -1)
        {
            entry = X509_NAME_get_entry(name, idx);
            str = X509_NAME_ENTRY_get_data(entry);
            ASN1_STRING_to_UTF8(&ou, str);
        }

        /* Get organization name */
        idx = X509_NAME_get_index_by_NID(name,
                                         NID_organizationName,
                                         -1);
        if (idx != -1)
        {
            entry = X509_NAME_get_entry(name, idx);
            str = X509_NAME_ENTRY_get_data(entry);
            ASN1_STRING_to_UTF8(&o, str);
        }

        /* Get country name */
        idx = X509_NAME_get_index_by_NID(name,
                                         NID_countryName,
                                         -1);
        if (idx != -1)
        {
            entry = X509_NAME_get_entry(name, idx);
            str = X509_NAME_ENTRY_get_data(entry);
            ASN1_STRING_to_UTF8(&c, str);
        }

        /* Form alternate common name */
        if (ou != NULL) cn_alt = g_strdup(ou);
        if (o != NULL)
        {
            if (cn_alt != NULL)
            {
                tmp = g_strconcat(cn_alt, CONCAT_STR, o,
                                  NULL);
                g_free(cn_alt);
                cn_alt = tmp;
                tmp = NULL;
            } else {
                cn_alt = g_strdup(o);
            }
        }

        if (c != NULL)
        {
            if (cn_alt != NULL)
            {
                tmp = g_strconcat(cn_alt, CONCAT_STR, c,
                                  NULL);
                g_free(cn_alt);
                cn_alt = tmp;
                tmp = NULL;
            } else {
                cn_alt = g_strdup(c);
            }
        }

        /* Free OU, O and C - all of them must be OPENSSL allocated! */
        if (ou != NULL) OPENSSL_free(ou);
        if (o != NULL) OPENSSL_free(o);
        if (c != NULL) OPENSSL_free(c);
    }

    if (longform == FALSE) {
        if (cn) {
            g_snprintf(result, INT_BUFSIZE, "%s", cn);
        } else if (cn_alt) {
            g_snprintf(result, INT_BUFSIZE, "%s", cn_alt);
        } else {
            DLOG_ERR("No certificate names found");
            result[0] = '\0';
        }

    }
    else { /* Construct longform identity out of available names */
        if (cn != NULL)
            if(cn_alt != NULL)
                g_snprintf(result, INT_BUFSIZE, "%s%s%s", cn, CONCAT_STR, cn_alt);
            else g_snprintf(result, INT_BUFSIZE, "%s", cn);
        else if (cn_alt != NULL)
            g_snprintf(result, INT_BUFSIZE, "%s", cn_alt);
        else {
            DLOG_ERR("No certificate names found");
            result[0] = '\0';
        }
    }

    /* Free cn and cn_alt, if necessary */
    if (cn != NULL) g_free(cn);
    if (cn_alt != NULL) g_free(cn_alt);

    return g_strdup(result);
}


gchar* get_certificate_name(X509* cert)
{
    return(X509_NAME_to_str(X509_get_subject_name(cert), FALSE));
}

gchar* get_purpose_name(const char* for_domain_name)
{
	int i;

	for (i = 0; NULL != pkcs12_targets[i].symbolic_name; i++) {
		if (0 == strcmp(pkcs12_targets[i].user_domain, for_domain_name)
			|| 0 == strcmp(pkcs12_targets[i].ca_domain, for_domain_name))
	    {
			return(_(pkcs12_targets[i].symbolic_name));
		}
	}
	return("(Unknown)");
}

