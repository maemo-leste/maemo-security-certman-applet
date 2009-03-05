/* -*- mode:c++; tab-width:4; c-basic-offset:4; -*- */
/**
   @file callbacks.c

   This module contains various callback handlers for handling events
   in the Certificate Manager CPA.
   <p>
   Copyright (c) 2005 Nokia. All rights reserved.

   @author  Karoliina T. Salminen <karoliina.t.salminen@nokia.com>
*/

#define _XOPEN_SOURCE

#include <osso-log.h>
#include <gconf/gconf-client.h>
#include <hildon/hildon.h>
#include <stdio.h>
#include <string.h>

#include "i18n.h"
#include "osso-applet-certman.h"
#include "interface.h"
#include "callbacks.h"

/* Implementation */

void 
cert_list_row_activated(GtkTreeView* tree,
						GtkTreePath* path,
						GtkTreeViewColumn* col,
						gpointer user_data)
{
    GtkTreeIter iter;
    GtkTreeModel *model = gtk_tree_view_get_model(tree);
    GtkWidget *window = NULL;
	GtkListStore *list_store = (GtkListStore*) user_data;
	gchar *name_str = NULL;
    gchar *cert_id  = NULL;
	gchar *domain   = NULL;
	maemosec_key_id cert_key;
	int rc, domain_flags;
	domain_handle dh = 0;
	X509 *cert = NULL;
	gboolean do_delete = FALSE;

    /* Set iterator to point to right node */
    if (!gtk_tree_model_get_iter(model, &iter, path))
    {
        return;
    }

    /* Get certificate ID */
    gtk_tree_model_get(model, &iter, 
					   MAIN_NAME_COL, &name_str, 
					   MAIN_ID_COL, &cert_id, 
					   MAIN_DOMAIN_COL, &domain,
					   MAIN_DOM_TYPE_COL, &domain_flags,
					   -1);

	MAEMOSEC_DEBUG(1, "%s:%s:%s:%s:%s", __func__, 
				   MAEMOSEC_CERTMAN_DOMAIN_SHARED==domain_flags?"shared":"private",
				   domain, cert_id, name_str);

	rc = maemosec_certman_open_domain(domain, domain_flags, &dh);
	if (0 != rc) {
		MAEMOSEC_ERROR("Cannot open domain '%s' (%d)", domain, rc);
		goto end;
	}

	rc = maemosec_certman_str_to_key_id(cert_id, cert_key);
	if (0 != rc) {
		MAEMOSEC_ERROR("Invalid cert key '%s' (%d)", cert_key, rc);
		goto end;
	}

	rc = maemosec_certman_load_cert(dh, cert_key, &cert);
	if (0 != rc) {
		MAEMOSEC_ERROR("Cannot get cert (%d)", rc);
		goto end;
	}

	maemosec_certman_close_domain(dh);
	dh = 0;

    window = gtk_widget_get_ancestor(GTK_WIDGET(tree),
                                     GTK_TYPE_WINDOW);

    do_delete = certmanui_certificate_details_dialog(window, domain_flags, cert);

	if (do_delete) {
		rc = maemosec_certman_open_domain(domain, domain_flags, &dh);
		if (0 == rc) {
			rc = maemosec_certman_rm_cert(dh, cert_key);
			if (0 == rc) {
				MAEMOSEC_DEBUG(1, "Certificate %s deleted", cert_id);
				if (gtk_list_store_remove(list_store, &iter)) {
					MAEMOSEC_DEBUG(1, "gtk_list_store_remove returned TRUE");
					gtk_tree_model_row_deleted(model, path);
				} else
					MAEMOSEC_DEBUG(1, "gtk_list_store_remove returned FALSE");
			}
			maemosec_certman_close_domain(dh);
			dh = 0;
		}
	}

 end:
	if (dh)
		maemosec_certman_close_domain(dh);
	if (cert)
		X509_free(cert);
	if (name_str)
		g_free(name_str);
	if (domain)
		g_free(domain);
	if (cert_id)
		g_free(cert_id);
	return;
}
