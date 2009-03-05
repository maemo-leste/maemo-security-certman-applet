/* -*- mode:c++; tab-width:4; c-basic-offset:4; -*- */
/**
   @file interface.c

   UI implementation for the Certificate Manager CPA.

   Copyright (c) 2005 Nokia. All rights reserved.

   @author  Karoliina T. Salminen <karoliina.t.salminen@nokia.com>
*/

#define _XOPEN_SOURCE

#include <libosso.h>
#include <osso-log.h>
#include <stdio.h>
#include <gtk/gtk.h>

#include <assert.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <maemosec_common.h>
#include <maemosec_certman.h>

#define __HILDON_REMOTE_TEXTURE_H__
#include <hildon/hildon.h>

#include "callbacks.h"
#include "interface.h"
#include "i18n.h"
#include "uidefs.h"
#include "uiutils.h"
#include "osso-applet-certman.h"

/* Local interface */

static void 
_create_certificate_list(GtkWidget** scroller,
						 GtkWidget** list,
						 GtkListStore** list_store);
static int 
_populate_certificates(int pos,
					   void* from_name,
					   void* store);

static void
_add_row_header(GtkListStore *list_store,
				const gchar* header_text);

/* Implementation */

GtkWidget* dialog = NULL;

GtkWidget* cert_list = NULL;
GtkListStore* cert_list_store = NULL;
GtkWidget* cert_scroller = NULL;

/*
 * TODO: Get rid of global variables
 */
GtkWindow* g_window = NULL;
static int domain_flags = MAEMOSEC_CERTMAN_DOMAIN_SHARED;

/* Other globals */
GdkGeometry hints;
RowParameter row_params[2];
ButtonParameter button_param;

/* These are found in details.c
   extern GtkWidget* cert_dialog;
   extern GtkWidget* cert_simple_dialog;
*/


GtkWidget* 
ui_create_main_dialog(gpointer window) 
{
	int rc;

    if (window == NULL)
    {
        return NULL;
    }
	g_window = window;

	MAEMOSEC_DEBUG(1, "Enter %s", __func__);

    /* Create dialog and set its attributes */
    dialog = gtk_dialog_new_with_buttons(_("cema_ap_application_title"),
                                         GTK_WINDOW(window),
                                         GTK_DIALOG_MODAL
                                         | GTK_DIALOG_DESTROY_WITH_PARENT
                                         | GTK_DIALOG_NO_SEPARATOR,
                                         NULL);

    if (NULL == dialog)
    {
        ULOG_ERR("Unable to create applet dialog.");
        return NULL;
    }

    /* Put width and height */
    hints.min_width  = MIN_WIDTH;
    hints.min_height = MIN_HEIGHT;
    hints.max_width  = MAX_WIDTH;
    hints.max_height = MAX_HEIGHT;

    gtk_window_set_geometry_hints(GTK_WINDOW(dialog), dialog, &hints,
                                  GDK_HINT_MIN_SIZE | GDK_HINT_MAX_SIZE);

    _create_certificate_list(&cert_scroller,
                             &cert_list,
                             &cert_list_store);

	GtkWidget *panarea = hildon_pannable_area_new();
	hildon_pannable_area_add_with_viewport(HILDON_PANNABLE_AREA(panarea),
										  GTK_WIDGET(cert_list));
    g_signal_connect(G_OBJECT(cert_list), 
					 "row-activated",
                     G_CALLBACK(cert_list_row_activated),
                     cert_list_store);

	MAEMOSEC_DEBUG(1, "Populate user certificates");
	_add_row_header(cert_list_store, "User");
	domain_flags = MAEMOSEC_CERTMAN_DOMAIN_PRIVATE;
	rc = maemosec_certman_iterate_domains(MAEMOSEC_CERTMAN_DOMAIN_PRIVATE,
										  _populate_certificates,
										  cert_list_store);


	MAEMOSEC_DEBUG(1, "Populate root certificates");
	_add_row_header(cert_list_store, "Authorities");
	domain_flags = MAEMOSEC_CERTMAN_DOMAIN_SHARED;
	rc = maemosec_certman_iterate_domains(MAEMOSEC_CERTMAN_DOMAIN_SHARED,
										  _populate_certificates,
										  cert_list_store);

    gtk_container_add(GTK_CONTAINER(GTK_DIALOG(dialog)->vbox), panarea);

	gtk_widget_show_all(dialog);

    return dialog;
}

void 
ui_refresh(void)
{
	;
}

void 
ui_destroy(void)
{
    if (dialog == NULL) 
		return;

    /* Delete main dialog */
    gtk_widget_destroy(dialog); 
	dialog = NULL;

    /* release pixbuf cache */
    release_pixbufs();
}

// typedef struct cert_info;

struct cert_info {
	struct cert_info* left;
	struct cert_info* right;
	gchar* nickname;
	gchar* sortname;
	gchar* key_str;
};

struct cert_display_info {
	const char* domain_name;
	int domain_type;
	struct cert_info* search_tree;
	GtkListStore* store;
	GtkTreeIter* iter;
};

struct sortname_info {
	char* buf;
	size_t bufmaxlen;
};

static void
add_name_component(unsigned char* comp, void* ctx)
{
	struct sortname_info* sif = (struct sortname_info*)ctx;

	if (NULL == comp || NULL == sif)
		return;
	if (strlen(sif->buf) + strlen((char*)comp) < sif->bufmaxlen)
		strcat(sif->buf, (char*)comp);
	else if (strlen(sif->buf) < sif->bufmaxlen) {
		memcpy(sif->buf + strlen(sif->buf), comp, 
			   sif->bufmaxlen - strlen(sif->buf) - 1);
		*(sif->buf + sif->bufmaxlen - 1) = '\0';
	}
}

const int sortname_nids [] = {
	NID_organizationName,
	NID_organizationalUnitName,
	NID_commonName
};

static int
fill_cert_data(int pos, X509* cert, void* info)
{
	struct cert_display_info *cd_info = (struct cert_display_info*) info;
	maemosec_key_id key_id;
	char namebuf[256] = "";
	char key_str[MAEMOSEC_KEY_ID_STR_LEN] = "";
	struct cert_info *cis, *add_point;
	struct sortname_info sif;
	int rc;
	char* c;

	MAEMOSEC_DEBUG(1, "Enter %d:%p:%p", pos, cert, info);

	rc = maemosec_certman_get_nickname(cert, namebuf, sizeof(namebuf));
	rc = maemosec_certman_get_key_id(cert, key_id);
	rc = maemosec_certman_key_id_to_str(key_id, key_str, sizeof(key_str));

	MAEMOSEC_DEBUG(3, "Add '%s:%s:%s:%s'", 
				   MAEMOSEC_CERTMAN_DOMAIN_SHARED==cd_info->domain_type?"shared":"private",
				   cd_info->domain_name, namebuf, key_str);

	cis = malloc(sizeof(struct cert_info));
	memset(cis, '\0', sizeof(struct cert_info));
	cis->nickname = g_strdup(namebuf);
	cis->key_str = g_strdup(key_str);

	sif.buf = namebuf;
	namebuf[0] = '\0';
	sif.bufmaxlen = sizeof(namebuf);
	pick_name_components_by_NIDS(X509_get_subject_name(cert), 
								 sortname_nids,
								 sizeof(sortname_nids)/sizeof(sortname_nids[0]),
								 add_name_component,
								 &sif);

	cis->sortname = g_strdup(namebuf);
	for (c = cis->sortname; *c; c++)
		*c = tolower(*c);
	
	MAEMOSEC_DEBUG(3, "Sortname '%s'", cis->sortname);

	/*
	 * Add the certificate into a binary search tree
	 */
	if (NULL == cd_info->search_tree)
		cd_info->search_tree = cis;
	else {
		add_point = cd_info->search_tree;
		while (add_point) {
			int cmp = strcmp(cis->sortname, add_point->sortname);
			if (0 > cmp) {
				if (add_point->left)
					add_point = add_point->left;
				else {
					add_point->left = cis;
					break;
				}
			} else {
				if (add_point->right)
					add_point = add_point->right;
				else {
					add_point->right = cis;
					break;
				}
			}
		}
	}
	return(0);
}


static void
_copy_search_tree(struct cert_info *node, struct cert_display_info* to_this)
{
	if (node->left)
		_copy_search_tree(node->left, to_this);
	MAEMOSEC_DEBUG(1, "%s", node->nickname);
	gtk_list_store_append(to_this->store, to_this->iter);
	gtk_list_store_set(to_this->store, to_this->iter, 
					   MAIN_NAME_COL, node->nickname, 
					   MAIN_PURPOSE_COL, get_purpose_name(to_this->domain_name), 
					   MAIN_ID_COL, node->key_str,
					   MAIN_DOMAIN_COL, to_this->domain_name,
					   MAIN_DOM_TYPE_COL, to_this->domain_type,
					   -1);
	if (node->right)
		_copy_search_tree(node->right, to_this);
}

static void
_release_search_tree(struct cert_info *node)
{
	g_free(node->nickname);
	g_free(node->sortname);
	g_free(node->key_str);
	if (node->left)
		_release_search_tree(node->left);
	if (node->right)
		_release_search_tree(node->right);
}


static int 
_populate_certificates(int pos, void* domain_name, void* store)
{
    GtkTreeIter iter;
    int rc;
	domain_handle my_domain;
	struct cert_display_info cd_info;

	MAEMOSEC_DEBUG(1, "Enter, open domain '%s'", (char*)domain_name);

	rc = maemosec_certman_open_domain((char*)domain_name, 
									  domain_flags,
									  &my_domain);

	MAEMOSEC_DEBUG(1, "%s(%s) ret %d", "maemosec_certman_open_domain",
				   (char*)domain_name, rc);
	if (0 != rc)
		return(rc);

	MAEMOSEC_DEBUG(1, "%s contains %d certificates", (char*)domain_name, 
				   maemosec_certman_nbrof_certs(my_domain));

	cd_info.domain_name = (char*)domain_name;
	cd_info.domain_type = domain_flags;
	cd_info.store = (GtkListStore*)store;
	cd_info.iter = &iter;
	cd_info.search_tree = NULL;

	rc = maemosec_certman_iterate_certs(my_domain, fill_cert_data, &cd_info);
	maemosec_certman_close_domain(my_domain);

	/*
	 * TODO: order newly appended certificate records
	 */
	if (cd_info.search_tree) {
		_copy_search_tree(cd_info.search_tree, &cd_info);
		_release_search_tree(cd_info.search_tree);
	}
	return(rc);
}


static gboolean
_is_row_header(GtkTreeModel *model,
			   GtkTreeIter *iter,
			   gchar** header_text,
			   gpointer data)
{
	gchar* title = NULL;
	gchar* key_str = NULL;
	gboolean result = FALSE;

	MAEMOSEC_DEBUG(4, "%s: Enter '%s' %p", __func__,
				   title = gtk_tree_path_to_string(gtk_tree_model_get_path(model,iter)),
				   data);
	g_free(title);
	gtk_tree_model_get(model, iter, MAIN_NAME_COL, &title, MAIN_ID_COL, &key_str, -1);
	if (NULL == key_str) {
		if (NULL != title) {
			MAEMOSEC_DEBUG(4, "%s: '%s' is row header", __func__, title);
			if (header_text)
				*header_text = g_strdup(title);
			result = TRUE;
		} else {
			MAEMOSEC_DEBUG(4, "%s: Title not set?", __func__);
		} 
	} else {
		MAEMOSEC_DEBUG(4, "%s: '%s' is not a row header", __func__, title?title:"???");
	}
	if (title)
		g_free(title);
	if (key_str)
		g_free(key_str);
	return(result);
}


static void
_add_row_header(GtkListStore *list_store,
				const gchar* header_text)
{
    GtkTreeIter iter;
	gtk_list_store_append(list_store, &iter);
	gtk_list_store_set(list_store, &iter, 
					   MAIN_NAME_COL,    header_text, 
#if 0
					   MAIN_PURPOSE_COL, " ",
					   MAIN_ID_COL,      NULL,
					   MAIN_DOMAIN_COL,  NULL,
#endif
					   -1);
}


static void 
_create_certificate_list(GtkWidget** scroller,
						 GtkWidget** list,
						 GtkListStore** list_store)
{
    GtkCellRenderer* renderer = NULL;
    GtkTreeViewColumn* column = NULL;
	gint wrap_width = 0;

    *list_store = gtk_list_store_new(MAIN_NUM_COLUMNS,
                                     G_TYPE_STRING,      /* MAIN_NAME_COL */
                                     G_TYPE_STRING,      /* MAIN_PURPOSE_COL */ 
									 G_TYPE_STRING,      /* MAIN_ID_COL (hidden) */
									 G_TYPE_STRING,      /* MAIN_DOMAIN_COL (hidden) */
									 G_TYPE_INT);        /* MAIN_DOM_TYPE_COL (hidden) */

    /* Create list */
    *list = gtk_tree_view_new_with_model(GTK_TREE_MODEL(*list_store));
    g_object_unref(*list_store);

    /* Create columns to the list */

    /* Certificate name column */
    renderer = gtk_cell_renderer_text_new();

    column = gtk_tree_view_column_new_with_attributes 
		(NULL, // _("cert_li_no_certificates_issuedto"),
		 renderer,
        "text", 
		 MAIN_NAME_COL,
		 NULL);

    gtk_tree_view_column_set_widget(column, NULL);
    gtk_tree_view_append_column (GTK_TREE_VIEW(*list), column);
	hildon_tree_view_set_row_header_func(GTK_TREE_VIEW(*list), _is_row_header, NULL, NULL);

#if 0
    g_object_set(G_OBJECT(column), "fixed-width", NAME_COL_WIDTH,
                 "sizing", GTK_TREE_VIEW_COLUMN_FIXED, NULL);
#endif

    /* Certificate purpose column */
	column = gtk_tree_view_column_new_with_attributes 
		(_("cert_li_no_certificates_purpose"),
		 renderer,
		 "text", 
		 MAIN_PURPOSE_COL,
		 NULL);
	gtk_tree_view_column_set_widget(column, NULL);
	gtk_tree_view_append_column (GTK_TREE_VIEW(*list), column);
	g_object_set(G_OBJECT(column), 
				 "fixed-width", 
				 PURPOSE_COL_WIDTH,
				 "sizing", 
				 GTK_TREE_VIEW_COLUMN_FIXED, 
				 NULL);

	gtk_window_get_size(GTK_WINDOW(g_window), &wrap_width, NULL);
	if (0 < wrap_width)
		wrap_width = (gint)(wrap_width - PURPOSE_COL_WIDTH - 60);
	else {
		/*
		 * Fallback
		 */
		MAEMOSEC_DEBUG(1, "%s: cannot compute word wrap length!", __func__);
		wrap_width = 240;
	}

	/* Wrap long names */
	g_object_set(G_OBJECT(renderer), 
				 "wrap-mode", PANGO_WRAP_WORD_CHAR, 
				 "wrap-width", wrap_width,
				 NULL);

#if 0	
	/* Order the list initially according to the last column */
	gtk_tree_view_column_clicked (column);
#endif

    gtk_tree_view_set_headers_visible(GTK_TREE_VIEW(*list), FALSE);

    return;
}
