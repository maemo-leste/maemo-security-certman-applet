/* -*- mode:c++; tab-width:4; c-basic-offset:4; -*- */
/**
   @file callbacks.c

   This module contains various callback handlers for handling events
   in the Certificate Manager CPA.
   <p>
   Copyright (c) 2005 Nokia. All rights reserved.

   @author  Karoliina T. Salminen <karoliina.t.salminen@nokia.com>
*/

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

void list_selection_changed(GtkTreeSelection *treeselection,
                            gpointer user_data)
{
    RowParameter* param = (RowParameter*)user_data;
    GtkTreeModel* model = GTK_TREE_MODEL(param->list);
    GtkTreeIter* iter = &(param->iter);

    /* Get selected item */
    param->iter_valid = gtk_tree_selection_get_selected (treeselection,
                                                         &model,
                                                         iter);

    if (param->iter_valid)
    {
        /* Selected row exists, enable buttons */
        gtk_widget_set_sensitive(param->export_button, TRUE);
        gtk_widget_set_sensitive(param->view_button, TRUE);

    } else {
        /* No selected rows, disable buttons */
        gtk_widget_set_sensitive(param->export_button, FALSE);
        gtk_widget_set_sensitive(param->view_button, FALSE);
    }
}


void 
import_button_clicked(GtkButton *button,
					  gpointer user_data)
{
    ButtonParameter* param = (ButtonParameter *)user_data;
    X509* x = NULL;
    maemosec_key_id cert_id;
    guint cid;
    GtkListStore* store = NULL;
    GtkTreeIter iter;

    GSList *pk12_list = NULL, *node = NULL;

    if (!certmanui_import_file(param->dialog, 
							   "file:///home/jum/MyDocs/wifiuser.pfx", 
							   NULL, NULL))
	//    if (certmanui_import_file(param->dialog, NULL, &cert_id, &pk12_list) != TRUE)
    {
        ULOG_ERR("certmanui_import_file() returned FALSE !!");
    }
	return;

    if (pk12_list != NULL) {
        /* Trying to refresh ui.. */
        for (node = pk12_list; node; node = node->next) {
            cid = *(maemosec_key_id *)node->data;
            g_free(node->data); node->data = NULL;
            /* fprintf(stderr, "cid = %d\n", cid); */
            gtk_list_store_append(store, &iter);
            gtk_list_store_set (store, &iter,
                                MAIN_ID_COL, cid,
                                -1);
            ui_refresh();
            X509_free(x);

        }
        /* ui_refresh(); */
        /* free list here */
        g_slist_free(pk12_list);
        return;
    }
    if (x == NULL)
    {
        ULOG_ERR("Unable to find the imported certificate");
        return;
    }
    gtk_list_store_append(store, &iter);
    gtk_list_store_set (store, &iter,
                        MAIN_ID_COL, cert_id,
                        -1);

    /* Update certificate information */
    ui_refresh();
    X509_free(x);
}


void export_button_clicked(GtkButton *button,
                           gpointer user_data)
{
    ButtonParameter* param = (ButtonParameter*)user_data;
    RowParameter rowparam;
    GtkNotebook* notebook = param->notebook;
    gint page = gtk_notebook_get_current_page(notebook);
    guint id;

    if (page < 0 || page > 1) {
        ULOG_ERR("Export button clicked, when not showing right page");
        return;
    } else {
        rowparam = param->rows[page];
    }

    if (!rowparam.iter_valid)
    {
        ULOG_ERR("Export button clicked, when selection not valid");
        return;
    }

    /* Get Certificate id from the right list */
    gtk_tree_model_get(GTK_TREE_MODEL(rowparam.list),
                       &rowparam.iter,
                       MAIN_ID_COL, &id,
                       -1);

    /* Show certificate export */
    certmanui_export_file(param->dialog, id);
}


static int
decode_key_id(gchar* from_buf, maemosec_key_id key_id)
{
	unsigned i = 0;
	unsigned short b;
	gchar* f = from_buf;

	if (!from_buf)
		return(0);

	while (*f && sscanf(f, "%02hX", &b)) {
		f += 2;
		if (*f == ':')
			f++;
		key_id[i++] = (unsigned char)b;
		if (i == MAEMOSEC_KEY_ID_LEN)
			break;
	}

	if (i < MAEMOSEC_KEY_ID_LEN) {
		return(0);
	} else
		return(1);
}


void 
view_button_clicked(GtkButton *button,
					gpointer user_data)
{
    ButtonParameter* param = (ButtonParameter*)user_data;
    RowParameter rowparam;
    GtkNotebook* notebook = param->notebook;
    gint page = gtk_notebook_get_current_page(notebook);
    gchar *domain_name, *key_str;
	domain_handle cert_domain;
	int domain_flags, rc;
    maemosec_key_id cert_id;
    X509* cert;

    if (page < 0 || page > 1) {
        ULOG_ERR("View button clicked, when not showing right page");
        return;

    } else {
        rowparam = param->rows[page];
		if (0 == page)
			domain_flags = MAEMOSEC_CERTMAN_DOMAIN_PRIVATE;
		else
			domain_flags = MAEMOSEC_CERTMAN_DOMAIN_SHARED;
    }

    if (!rowparam.iter_valid)
    {
        ULOG_ERR("View button clicked, when selection not valid");
        return;
    }

    /* Get Certificate id from the right list */
    gtk_tree_model_get(GTK_TREE_MODEL(rowparam.list),
                       &rowparam.iter,
                       MAIN_DOMAIN_COL, &domain_name,
                       -1);
    MAEMOSEC_DEBUG(1, "Domain: %s", domain_name);

    gtk_tree_model_get(GTK_TREE_MODEL(rowparam.list),
                       &rowparam.iter,
                       MAIN_ID_COL, &key_str,
                       -1);
    MAEMOSEC_DEBUG(1, "Key id: %s", key_str);
	decode_key_id(key_str, cert_id);
    g_free(key_str);

	// TODO: private or shared?
	rc = maemosec_certman_open_domain(domain_name,
									  domain_flags,
									  &cert_domain);
    g_free(domain_name);
	if (0 != rc) {
		MAEMOSEC_ERROR("Cannot open domain '%s'", domain_name);
		return;
	}
	
	MAEMOSEC_DEBUG(1, "Retrieve");
	rc = maemosec_certman_load_cert(cert_domain, cert_id, &cert);
	if (0 != rc) {
		MAEMOSEC_ERROR("Cannot load certificate");
		maemosec_certman_close_domain(cert_domain);
		return;
	}
	maemosec_certman_close_domain(cert_domain);
	MAEMOSEC_DEBUG(1, "Retrieved");

    /* Show certificate details and updated info */
    certmanui_certificate_details_dialog(param->dialog, FALSE, cert);
	X509_free(cert);

}


void notebook_switch_page(GtkNotebook* notebook,
                          GtkNotebookPage* page,
                          guint page_num,
                          gpointer user_data)
{
    ButtonParameter* param = (ButtonParameter*)user_data;
    RowParameter* rowparam;
    GtkTreeIter iter;

    if (page_num < 0 || page_num > 1) {
        /* Disable view/export/import buttons */
        rowparam = &(param->rows[0]);
        gtk_widget_set_sensitive(rowparam->view_button, FALSE);
        gtk_widget_set_sensitive(rowparam->import_button, FALSE);
        gtk_widget_set_sensitive(rowparam->export_button, FALSE);
        return;
    } else {
        rowparam = &(param->rows[page_num]);
    }

    /* Check if there is rows in the list of the current page */
    if (!gtk_tree_model_get_iter_first(GTK_TREE_MODEL(rowparam->list),
                                       &iter))
    {
        /* iter_valid should already be FALSE if we are here, but
           set it to be sure*/
        rowparam->iter_valid = FALSE;

        gtk_widget_set_sensitive(rowparam->import_button, TRUE);
    } else {
        if (!gtk_tree_selection_get_selected (
                gtk_tree_view_get_selection(rowparam->view),
                NULL, NULL))
        {
            gtk_tree_selection_select_iter(
                gtk_tree_view_get_selection(rowparam->view), &iter);
            /* Here the selection change callback will put
               iter_valid to TRUE. If we are not in this
               if then iter_valid should be already TRUE, but
               nothing realy bad should happend if it is not by
               some strange reason. */
        }
        gtk_widget_set_sensitive(rowparam->import_button, TRUE);
    }
    gtk_widget_set_sensitive(rowparam->view_button, rowparam->iter_valid);
    gtk_widget_set_sensitive(rowparam->export_button, rowparam->iter_valid);
}


void cert_list_row_activated(GtkTreeView* tree,
                             GtkTreePath* path,
                             GtkTreeViewColumn* col,
                             gpointer user_data)
{
    GtkTreeIter iter;
    GtkTreeModel* model = gtk_tree_view_get_model(tree);
    GtkWidget* window = NULL;
    RowActivatedParameter* param = (RowActivatedParameter*)user_data;
	gchar* name_str = NULL;
    gchar* cert_id  = NULL;
	gchar* domain   = NULL;
	maemosec_key_id cert_key;
	int rc;
	domain_handle dh = 0;
	X509* cert = NULL;

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
					   -1);

	MAEMOSEC_DEBUG(1, "%s: %s:%s:%s", __func__, domain, cert_id, name_str);

	/*
	 * TODO: delivery also the domain type
	 */
	rc = maemosec_certman_open_domain(domain, MAEMOSEC_CERTMAN_DOMAIN_SHARED,
									  &dh);
	if (0 != rc)
		rc = maemosec_certman_open_domain(domain, MAEMOSEC_CERTMAN_DOMAIN_PRIVATE,
										  &dh);
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

    certmanui_certificate_details_dialog(window, TRUE, cert);

#if 0
    update_info(AUTH_ROOT, NULL, cert_id, UPDATE_ALL);
    update_info(AUTH_USER, NULL, cert_id, UPDATE_ALL);
#endif
    ui_refresh();

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


gboolean cert_list_button_pressed(GtkWidget *widget,
                                  GdkEventButton *event,
                                  gpointer user_data)
{
    GtkTreeSelection* selection = NULL;
    GtkTreeIter iter;
    GtkTreePath* path = NULL;
    GtkTreeView* tree = GTK_TREE_VIEW(widget);
    GtkTreeModel* model = NULL;


    if (tree == NULL) return FALSE;

    /* Check if initiate row-activated. Now activated when double clicked. */
    if (event->type == GDK_2BUTTON_PRESS)
    {
        /* Get selected row from the tree */
        selection = gtk_tree_view_get_selection(tree);
        if (!gtk_tree_selection_get_selected(selection, &model,
                                             &iter))
        {
            return FALSE;
        }

        path = gtk_tree_model_get_path(model, &iter);

        cert_list_row_activated(tree, path, NULL, user_data);

        gtk_tree_path_free(path);
    }

    return FALSE;
}


void default_insensitive_press(GtkWidget* widget,
                               gpointer data)
{
    if (((gchar*)data) == NULL) return;

    hildon_banner_show_information (NULL, NULL, (gchar*)data) ;
}
