/* -*- mode:c; tab-width:4; c-basic-offset:4; -*- 
 *
 * This file is part of maemo-security-certman-applet
 *
 * Copyright (C) 2009 Nokia Corporation and/or its subsidiary(-ies).
 *
 * Contact: Juhani Mäkelä <ext-juhani.3.makela@nokia.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 *
 */

#include "cm_dialogs.h"

#include <libosso.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include <gtk/gtk.h>
#include <gdk/gdkkeysyms.h>
#include <libcomapp/comapp_opensave.h>

#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <maemosec_common.h>
#include <maemosec_certman.h>

#include "i18n.h"
#include "osso-applet-certman.h"
#include "cm_envelopes.h"

extern long timezone;

/*
 * Certificates can be imported from files of these types
 */
static gchar *cert_mimetypes[] = {
    "application/x-osso-applet-certman",
    "application/x-x509-ca-cert",
    "application/x-pkcs12",
    "application/pkcs7-mime",
    "application/pkcs7-signature",
    NULL};

/* Certificate list colums */
enum {
    MAIN_NAME_COL = 0,
    MAIN_ID_COL,
    MAIN_DOMAIN_COL,
    MAIN_DOM_TYPE_COL,
    MAIN_CONTENT_COL,
    MAIN_NUM_COLUMNS
};

/* Size for the main dialog */
#define MIN_WIDTH               592
#define MIN_HEIGHT              360
#define MAX_WIDTH               800
#define MAX_HEIGHT              404

/* Size for the details dialog */
#define DETAILS_MIN_WIDTH       482
#define DETAILS_MIN_HEIGHT      360
#define DETAILS_MAX_WIDTH       800
#define DETAILS_MAX_HEIGHT      404

#define ICONSIZE                HILDON_ICON_PIXEL_SIZE_SMALL

#define NAMEBUF_LEN             256
#define MAX_TITLE_NAME_LEN      72
#define MAX_DIGEST_LEN          128

/*
 * User-defined response codes
 */
#define GTK_RESPONSE_CHANGE_PASSWORD 1001
#define GTK_RESPONSE_RM_CERTIFICATE  1002
/*
 * When password protection is turned off, 
 * use still something to encrypt the PCKCS#8
 * container. Otherwise connectivity doesn't work.
 */
#define DEFAULT_PASSWORD "AeHi5ied"

/* Local interface */

struct cert_info {
	struct cert_info* left;
	struct cert_info* right;
	gchar* nickname;
    gchar* usage;
	gchar* sortname;
	gchar* key_str;
	gchar* domain_name;
    gboolean is_valid;
};

struct sortname_info {
	char* buf;
	size_t bufmaxlen;
};

struct populate_context {
	int domain_flags;
	const char* domain_name;
	GtkListStore *store;
	GtkTreeIter* iter;
    struct cert_info* search_tree;
};

static struct import_context {
    gpointer window;
    GtkListStore* list_store;
    GtkTreeView* tree;
} import_context;

static int
_split_string(gchar* string, gchar separator, GList** to_list);
static int
_list_difference(GList* in_this, GList* but_not_in_this, GList** copy_here);
static void
_join(GList* the_list, gchar* with_separator, gchar** to_string);

static void 
_create_certificate_list(GtkWidget** list,
						 GtkListStore** list_store);

static int 
_populate_certificates(int pos,
                       void* domain_name,
					   void* ctx);
static void
_populate_all_certificates(GtkListStore* cert_list_store);

static void
_copy_search_tree(struct cert_info* from_tree, 
                  struct populate_context *to_ctx);

static void
_release_search_tree(struct cert_info *node);

static void
_add_row_header(GtkListStore *list_store,
				const gchar* header_text);

static void 
_expired_dialog_response(GtkDialog* dialog,
                         gint response_id,
                         gpointer data);

static void 
_infonote_dialog_response(GtkDialog* dialog,
                          gint response_id,
                          gpointer data);
static void 
cert_list_row_activated(GtkTreeView* tree,
						GtkTreePath* path,
						GtkTreeViewColumn* col,
						gpointer user_data);
static void
_import_certificate(GtkAction *action, 
                    struct import_context *ctx);

static int
X509_check_cert_time(X509* cert);

static gboolean
ask_domains(gpointer window, 
			GtkWidget **dialog,
			GList** domains);

static gboolean 
_certificate_details(gpointer window,
                     int domain_flags,
                     X509* cert);

static GtkWidget* 
_create_infobox(gpointer window, 
                X509* cert, 
                gchar** btn_label);

static void _add_labels(GtkTable* table, 
                        gint* row,
                        const gchar* label, 
                        const gchar* value, 
                        gboolean wrap);

/** Generic callback parameter */
typedef struct {
    CertificateExpiredResponseFunc callback;
    gpointer user_data;
} CallbackParameter;

/* Implementation */
/*
 * TODO: Get rid of global variables
 */

GtkWidget* cert_list = NULL;
GtkListStore* cert_list_store = NULL;
osso_context_t *osso_global;
GtkWindow* g_window = NULL;
GdkGeometry hints;

/*
 * There are eight predefined certificate stores that
 * can be manipulated by this applet, two for each use.
 * the <use>-user store contains user certificates and
 * <use>-ca store the signing certificates.
 */
struct pkcs12_target {
	gchar* symbolic_name;
	gchar* domain_name;
};

#define USER_DOMAIN_FMT "%s-user"
#define CA_DOMAIN_FMT   "%s-ca"
#define IMPORT_NEW_DOMAIN "##import-new"

const struct pkcs12_target pkcs12_targets [] = {
	{
		.symbolic_name = "cert_nc_purpose_ssl_tls", 
		.domain_name = "ssl"
	},
	{
		.symbolic_name = "cert_nc_purpose_wlan_eap", 
		.domain_name = "wifi"
	},
	{
		.symbolic_name = "cert_nc_purpose_email_smime", 
		.domain_name = "smime" 
	},
#if 0
	/* 
	 * X.509 is not used for package signing in Fremantle
	 */
	{
		.symbolic_name = "cert_nc_purpose_software_signing", 
		.domain_name = "ssign"
	},
#endif
	{
		.symbolic_name = NULL,
		.domain_name = NULL
	}
};

gboolean 
certmanui_init(osso_context_t *osso_ext) 
{
	osso_global = osso_ext;
	MAEMOSEC_DEBUG(1, "%s => %p", __func__, osso_ext);
	return(TRUE);
}

gboolean 
certmanui_deinit(void) 
{
	osso_global = NULL;
	MAEMOSEC_DEBUG(1, "%s", __func__);
	maemosec_certman_close(NULL);
    return(TRUE);
}


GtkWidget* 
ui_create_main_dialog(gpointer window) 
{
	GtkWidget* main_dialog = NULL;

	MAEMOSEC_DEBUG(1, "Enter %s", __func__);

    if (window == NULL)
    {
		MAEMOSEC_DEBUG(1, "%s: NULL window, exit", __func__);
        return NULL;
    }
	g_window = window;
    MAEMOSEC_DEBUG(1, "%s: main window is %p", __func__, window);

    /* Create dialog and set its attributes */
    main_dialog = gtk_dialog_new_with_buttons(_("cema_ap_application_title"),
                                         GTK_WINDOW(window),
                                         GTK_DIALOG_DESTROY_WITH_PARENT
                                         | GTK_DIALOG_NO_SEPARATOR,
                                         NULL);
    if (NULL == main_dialog)
    {
        MAEMOSEC_ERROR("Unable to create applet dialog.");
        return NULL;
    }
	MAEMOSEC_DEBUG(1, "Created main dialog");

    /* Put width and height */
    hints.min_width  = MIN_WIDTH;
    hints.min_height = MIN_HEIGHT;
    hints.max_width  = MAX_WIDTH;
    hints.max_height = MAX_HEIGHT;

    gtk_window_set_geometry_hints(GTK_WINDOW(main_dialog), main_dialog, &hints,
                                  GDK_HINT_MIN_SIZE | GDK_HINT_MAX_SIZE);
	MAEMOSEC_DEBUG(1, "Set geometry hints");

    _create_certificate_list(&cert_list,
                             &cert_list_store);
	MAEMOSEC_DEBUG(1, "Created certificate lists");
    g_signal_connect(G_OBJECT(cert_list), 
					 "row-activated",
                     G_CALLBACK(cert_list_row_activated),
                     cert_list_store);

    /*
     * Add a button to import a new certificate
     */
    GtkWidget *import_button = hildon_button_new (HILDON_SIZE_AUTO_WIDTH | HILDON_SIZE_FINGER_HEIGHT, 
                                                  HILDON_BUTTON_ARRANGEMENT_HORIZONTAL);
    hildon_button_set_title(HILDON_BUTTON(import_button), _("cert_ti_main_notebook_import"));

    GdkPixbuf *import_pixbuf = gtk_icon_theme_load_icon
        (gtk_icon_theme_get_default(), "general_add", ICONSIZE, GTK_ICON_LOOKUP_NO_SVG, NULL);
    if (import_pixbuf) {
        hildon_button_set_image(HILDON_BUTTON(import_button), gtk_image_new_from_pixbuf(import_pixbuf));
        g_object_unref(import_pixbuf);
    }
    import_context.window = window;
    import_context.tree = GTK_TREE_VIEW(cert_list);
    import_context.list_store = cert_list_store;
    g_signal_connect(G_OBJECT(import_button), "clicked", G_CALLBACK(_import_certificate), 
                     &import_context);

	GtkWidget *panarea = hildon_pannable_area_new();

    gtk_box_pack_start(GTK_BOX(hildon_tree_view_get_action_area_box(GTK_TREE_VIEW(cert_list))),
                       import_button, TRUE, TRUE, 0);
    hildon_tree_view_set_action_area_visible(GTK_TREE_VIEW(cert_list), TRUE);
    gtk_container_add(GTK_CONTAINER(panarea), cert_list);
    gtk_container_add(GTK_CONTAINER(GTK_DIALOG(main_dialog)->vbox), panarea);

    _populate_all_certificates(cert_list_store);

	MAEMOSEC_DEBUG(1, "Show all");
	gtk_widget_show_all(main_dialog);

    return main_dialog;
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

	gtk_tree_model_get(model, iter, 
					   MAIN_NAME_COL, &title, 
					   MAIN_ID_COL, &key_str, -1);

	if (NULL == key_str) {
		if (NULL != title) {
			if (header_text) {
				*header_text = g_strdup(title);
			}
            result = TRUE;
		}
	}
	if (title)
		g_free(title);
	if (key_str)
		g_free(key_str);
	return(result);
}


static void 
_create_certificate_list(GtkWidget** list,
						 GtkListStore** list_store)
{
    GtkCellRenderer* renderer = NULL;
    GtkTreeViewColumn* column = NULL;

    *list_store = gtk_list_store_new(MAIN_NUM_COLUMNS,
                                     G_TYPE_STRING,      /* MAIN_NAME_COL */
									 G_TYPE_STRING,      /* MAIN_ID_COL (hidden) */
									 G_TYPE_STRING,      /* MAIN_DOMAIN_COL (hidden) */
									 G_TYPE_INT,         /* MAIN_DOM_TYPE_COL (hidden) */
									 G_TYPE_STRING);     /* MAIN_CONTENT_COL (hidden) */

    /* Create list */
    *list = gtk_tree_view_new_with_model(GTK_TREE_MODEL(*list_store));
    g_object_unref(*list_store);

    /* Create columns to the list */

    /* Certificate name column */
    renderer = gtk_cell_renderer_text_new();

    column = gtk_tree_view_column_new_with_attributes 
		(NULL,
		 renderer,
        "markup", 
		 MAIN_NAME_COL,
		 NULL);

    gtk_tree_view_column_set_widget(column, NULL);
    gtk_tree_view_append_column (GTK_TREE_VIEW(*list), column);
	hildon_tree_view_set_row_header_func(GTK_TREE_VIEW(*list), 
										 _is_row_header, NULL, NULL);

	g_object_set(G_OBJECT(renderer), 
				 "ellipsize", PANGO_ELLIPSIZE_END, 
				 "ellipsize-set", TRUE,
                 NULL);

    gtk_tree_view_set_headers_visible(GTK_TREE_VIEW(*list), FALSE);
}


static void
_populate_all_certificates(GtkListStore* cert_list_store)
{
    GtkTreeIter iter;
	const struct pkcs12_target *tgt;
	char domain_name[NAMEBUF_LEN];
	struct populate_context pc;
	int rc;


    MAEMOSEC_DEBUG(1, "%s: enter", __func__);

	MAEMOSEC_DEBUG(1, "%s: populate user certificates", __func__);

	pc.store = cert_list_store;
    pc.iter = &iter;
	pc.domain_flags = MAEMOSEC_CERTMAN_DOMAIN_PRIVATE;
    pc.domain_name = NULL;
    pc.search_tree = NULL;

	for (tgt = pkcs12_targets; tgt->symbolic_name; tgt++) {
		snprintf(domain_name, sizeof(domain_name), USER_DOMAIN_FMT, tgt->domain_name);
		_populate_certificates(0, domain_name, &pc);
	}

	if (NULL != pc.search_tree) {
		/*
		 * Add header only if there are some user certificates installed
		 */
        _add_row_header(cert_list_store, _("cert_ti_main_notebook_user"));
		_copy_search_tree(pc.search_tree, &pc);
		_release_search_tree(pc.search_tree);
        pc.search_tree = NULL;
	}

	MAEMOSEC_DEBUG(1, "Populate user modifiable CA certificates");

    /*
     * Let's assume that there always is some CA certificates
     */
    _add_row_header(cert_list_store, _("cert_ti_main_notebook_authorities"));
	for (tgt = pkcs12_targets; tgt->symbolic_name; tgt++) {
		snprintf(domain_name, sizeof(domain_name), CA_DOMAIN_FMT, tgt->domain_name);
		_populate_certificates(0, domain_name, &pc);
	}

	if (NULL != pc.search_tree) {
		_copy_search_tree(pc.search_tree, &pc);
		_release_search_tree(pc.search_tree);
        pc.search_tree = NULL;
	}

	MAEMOSEC_DEBUG(1, "Populate root CA certificates");
	pc.domain_flags = MAEMOSEC_CERTMAN_DOMAIN_SHARED;

	rc = maemosec_certman_iterate_domains(MAEMOSEC_CERTMAN_DOMAIN_SHARED,
										  _populate_certificates,
										  &pc);

	if (NULL != pc.search_tree) {
		_copy_search_tree(pc.search_tree, &pc);
		_release_search_tree(pc.search_tree);
	}

    MAEMOSEC_DEBUG(1, "%s: exit", __func__);
}


static void
sortname_add_name_component(unsigned char* comp, void* ctx)
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

/*
 * Sort according to a name built like this
 */
const int sortname_nids [] = {
	NID_organizationName,
	NID_organizationalUnitName,
	NID_commonName
};

/*
 * Show these in the details view
 */
static const int fullname_components [] = {
	NID_pkcs9_emailAddress, 
	NID_commonName, 
	NID_organizationalUnitName, 
	NID_organizationName
};

static void
pick_name_components_by_NIDS(X509_NAME* of_name, 
							 const int* nids, 
							 unsigned nbrofnids, 
							 void cb_func(unsigned char*,void*),
							 void* ctx)
{
	unsigned i;

	if (NULL == of_name || 0 == nbrofnids )
		return;

	for (i = 0; i < nbrofnids; i++) {
		int idx;
		idx = X509_NAME_get_index_by_NID(of_name, nids[i], -1);
		if (-1 != idx) {
			X509_NAME_ENTRY *entry = NULL;
			entry = X509_NAME_get_entry(of_name, idx);
			if (NULL != entry) {
				ASN1_STRING *str = NULL;
				str = X509_NAME_ENTRY_get_data(entry);
				if (NULL != str) {
					unsigned char *quark = NULL;
					ASN1_STRING_to_UTF8(&quark, str);
					if (NULL != quark) {
						cb_func(quark, ctx);
						OPENSSL_free(quark);
					}
				}
			}
		}
	}
}

/*
 * A generic function to pick name components
 */
#define STR_ARR_END_MARK (gchar*)-1

static void
add_to_str_arr(unsigned char* namepart, void* data)
{
    gchar** str_arr = (gchar**) data;
    int i;
    for (i = 0; NULL != str_arr[i] && STR_ARR_END_MARK != str_arr[i]; i++);
    if (STR_ARR_END_MARK != str_arr[i])
        str_arr[i] = g_strdup((char*)namepart);
}


static gchar* 
get_purpose_name(const char* for_domain_name)
{
	int i;

	for (i = 0; NULL != pkcs12_targets[i].symbolic_name; i++) {
		if (strlen(for_domain_name) >= strlen(pkcs12_targets[i].domain_name)
			&& 0 == memcmp(pkcs12_targets[i].domain_name, 
						   for_domain_name,
						   strlen(pkcs12_targets[i].domain_name)))
	    {
			return(_(pkcs12_targets[i].symbolic_name));
		}
	}
	return("");
}

static gchar*
get_user_cert_name(X509* cert)
{
    int rc;
    gchar *cert_name;
    gchar *name_parts [3] = {NULL, NULL, STR_ARR_END_MARK};
            
    pick_name_components_by_NIDS(X509_get_subject_name(cert), 
                                 fullname_components,
                                 sizeof(fullname_components)/sizeof(int), 
                                 add_to_str_arr,
                                 name_parts);
    if (NULL != name_parts[1]) {
        cert_name = g_strdup_printf("%s (%s)", name_parts[1], name_parts[0]);
        g_free(name_parts[0]);
        g_free(name_parts[1]);
    } else if (NULL != name_parts[0]) {
        cert_name = g_strdup(name_parts[0]);
        g_free(name_parts[0]);
    } else {
        char temp [NAMEBUF_LEN] = "";
        rc = maemosec_certman_get_nickname(cert, temp, sizeof(temp));
        cert_name = g_strdup(temp);
    }
    return cert_name;
}


static gchar*
_cert_item_label(gboolean is_valid, gchar* nickname, gchar* usages)
{
    gchar *res;

    if (is_valid) {
        res = g_strdup_printf("<markup><b>%s</b>\n<small>%s %s</small></markup>", 
                              nickname,
                              _("cert_ti_main_notebook_validfor"),
                              usages);
    } else {
        gchar *emesg = g_strdup(_("cert_nc_expired"));
        gchar *c = strchr(emesg, '\n');
        if (c)
            *c = '\0';
        res = g_strdup_printf("<markup><b>%s</b>\n<small><span color=\"red\">"
                              "%s</span></small></markup>", 
                              nickname,
                              emesg);
        g_free(emesg);
    }
    return res;
}


static void
_copy_search_tree(struct cert_info* from_tree, struct populate_context *to_ctx)
{
	if (from_tree->left)
		_copy_search_tree(from_tree->left, to_ctx);

	MAEMOSEC_DEBUG(1, "%s", from_tree->nickname);
	gtk_list_store_append(to_ctx->store, to_ctx->iter);
	gtk_list_store_set(to_ctx->store, to_ctx->iter, 
					   MAIN_NAME_COL, _cert_item_label
                       (from_tree->is_valid, from_tree->nickname, from_tree->usage),
					   MAIN_ID_COL, from_tree->key_str,
					   MAIN_DOMAIN_COL, from_tree->domain_name,
					   MAIN_DOM_TYPE_COL, to_ctx->domain_flags,
					   -1);

	if (from_tree->right)
		_copy_search_tree(from_tree->right, to_ctx);
}


static void
_release_search_tree(struct cert_info *node)
{
	g_free(node->nickname);
	g_free(node->domain_name);
	g_free(node->sortname);
	g_free(node->usage);
	g_free(node->key_str);
	if (node->left)
		_release_search_tree(node->left);
	if (node->right)
		_release_search_tree(node->right);
}


static int
fill_cert_data(int pos, X509* cert, void* info)
{
	struct populate_context *pc = (struct populate_context*) info;
	maemosec_key_id key_id;
	char namebuf[NAMEBUF_LEN] = "";
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
				   MAEMOSEC_CERTMAN_DOMAIN_SHARED==pc->domain_flags?"shared":"private",
				   pc->domain_name, namebuf, key_str);

	cis = malloc(sizeof(struct cert_info));
	memset(cis, '\0', sizeof(struct cert_info));
    cis->domain_name = g_strdup(pc->domain_name);
	cis->nickname = g_strdup(namebuf);
#if 0
    if (MAX_TITLE_NAME_LEN < strlen(cis->nickname)) {
        char* sep = cis->nickname + MAX_TITLE_NAME_LEN;
        while ((sep > (cis->nickname + MAX_TITLE_NAME_LEN/2)) && (' ' != *sep))
            sep--;
        if (' ' != *sep) {
            sep = cis->nickname + MAX_TITLE_NAME_LEN - 4;
            strcpy(sep, "...");
        } else
            *sep = '\0';
    }
#endif
    if (MAEMOSEC_CERTMAN_DOMAIN_SHARED == pc->domain_flags)
        cis->usage = g_strdup(_("cert_ti_main_notebook_allusers"));
    else {
        cis->usage = g_strdup(get_purpose_name(pc->domain_name));
    }
	cis->key_str  = g_strdup(key_str);
    cis->is_valid = (0 == X509_check_cert_time(cert));

	sif.buf = namebuf;
	namebuf[0] = '\0';
	sif.bufmaxlen = sizeof(namebuf);
	pick_name_components_by_NIDS(X509_get_subject_name(cert), 
								 sortname_nids,
								 sizeof(sortname_nids)/sizeof(sortname_nids[0]),
								 sortname_add_name_component,
								 &sif);

	cis->sortname = g_strdup(namebuf);
	for (c = cis->sortname; *c; c++)
		*c = tolower(*c);
	
	MAEMOSEC_DEBUG(3, "Sortname '%s'", cis->sortname);

	/*
	 * Add the certificate into a binary search tree
	 */
	if (NULL == pc->search_tree)
		pc->search_tree = cis;
	else {
		add_point = pc->search_tree;
		while (add_point) {
			int cmp;

            /*
             * If the certificate is already in the search tree, 
             * just append to the usage code and domain in stead of 
             * adding a new node.
             */
            if (0 == strcmp(cis->key_str, add_point->key_str)) {
                gchar* tmp = add_point->usage;
                add_point->usage = g_strdup_printf("%s, %s", tmp, cis->usage);
                g_free(tmp);
                tmp = add_point->domain_name;
                add_point->domain_name = g_strdup_printf("%s,%s", tmp, cis->domain_name);
                g_free(tmp);
                _release_search_tree(cis);
                break;
            }

            cmp = strcmp(cis->sortname, add_point->sortname);
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


static int 
_populate_certificates(int pos, void* domain_name, void* ctx)
{
    int rc;
	domain_handle my_domain;
	struct populate_context *pc = (struct populate_context*)ctx;

	MAEMOSEC_DEBUG(1, "Enter, open domain '%s'", (char*)domain_name);

	rc = maemosec_certman_open_domain((char*)domain_name, 
									  pc->domain_flags,
									  &my_domain);

	MAEMOSEC_DEBUG(1, "%s(%s) ret %d", "maemosec_certman_open_domain",
				   (char*)domain_name, rc);
	if (0 != rc)
		return(rc);

	MAEMOSEC_DEBUG(1, "%s contains %d certificates", (char*)domain_name, 
				   maemosec_certman_nbrof_certs(my_domain));

    pc->domain_name = domain_name;
	rc = maemosec_certman_iterate_certs(my_domain, fill_cert_data, pc);
	maemosec_certman_close_domain(my_domain);

	/*
	 * Continue iteration even if there are invalid domains.
	 */
	return(0);
}


static void
_add_row_header(GtkListStore *list_store,
				const gchar* header_text)
{
    GtkTreeIter iter;
	gtk_list_store_append(list_store, &iter);
	gtk_list_store_set(list_store, &iter, 
					   MAIN_NAME_COL, header_text, 
					   -1);
}


static GtkWidget* 
create_scroller(GtkWidget* child)
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


static gchar*
get_new_password(gpointer window) 
{
    HildonSetPasswordDialog* new_password_dialog = NULL;
	gchar* result = NULL;
	gint response;

	MAEMOSEC_DEBUG(1, "%s: Enter", __func__);
	new_password_dialog = HILDON_SET_PASSWORD_DIALOG
        (hildon_set_password_dialog_new(window, TRUE));
	gtk_widget_show_all(GTK_WIDGET(new_password_dialog));
	do {
		response = gtk_dialog_run(GTK_DIALOG(new_password_dialog));
        MAEMOSEC_DEBUG(1, "%s: gtk_dialog_run returned %d", __func__, response);

		if (GTK_RESPONSE_OK == response) {
			result = g_strdup(hildon_set_password_dialog_get_password
                              (new_password_dialog));
			MAEMOSEC_DEBUG(1, "%s: changed password to '%s'", __func__, result);
			break;
		}
	} while (GTK_RESPONSE_DELETE_EVENT != response);

	gtk_widget_hide_all(GTK_WIDGET(new_password_dialog));
	gtk_widget_destroy(GTK_WIDGET(new_password_dialog));
	return(result);
}


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

#define INSTALL_CERT 0x08000000

static gboolean
_certificate_details(gpointer window,
					 int domain_flags,
					 X509* cert)
{
    GtkWidget* cert_dialog = NULL;
	GtkWidget *bn_button = NULL;
	GtkWidget *change_password_button = NULL;

    GdkGeometry hints;
    GtkWidget* infobox = NULL;
    GtkWidget* scroller = NULL;
    GtkRequisition requisition;
	gchar *dlg_title, *btn_label;
    gint ret = 0;
	gboolean result = FALSE;

    if (osso_global == NULL)
    {
        MAEMOSEC_ERROR("osso_global is NULL");
        return FALSE;
    }

	MAEMOSEC_DEBUG(1, "%s: window is %p", __func__, window);

	if (MAEMOSEC_CERTMAN_DOMAIN_PRIVATE == domain_flags) {
		dlg_title = _("cert_ti_viewing_dialog");
		btn_label = _("cert_ti_application_trust");

	} else if (MAEMOSEC_CERTMAN_DOMAIN_SHARED == domain_flags) {
		dlg_title = _("cert_ti_viewing_dialog");
		btn_label = NULL;

	} else if (INSTALL_CERT == domain_flags) {
		dlg_title = _("cert_ti_install_certificate");
		btn_label = _("cert_bd_cd_install");

	} else {
		dlg_title = _("cert_ti_install_certificate");
		btn_label = NULL;
	}

    cert_dialog = gtk_dialog_new_with_buttons(dlg_title,
                                              GTK_WINDOW(window),
                                              GTK_DIALOG_DESTROY_WITH_PARENT
                                              | GTK_DIALOG_NO_SEPARATOR,
                                              NULL);

    if (cert_dialog == NULL) {
        MAEMOSEC_ERROR("Failed to create dialog");
        return(FALSE);
    }

    infobox = _create_infobox(window, cert, &btn_label);

    /* Unable to open certificate, give error and exit */
    if (infobox == NULL)
    {
		MAEMOSEC_DEBUG(1, "Failed to create infobox");
		gtk_widget_destroy(cert_dialog);
        return(FALSE);
    }

	/*
	 * Allow deleting invalid certificates
	 */
	if (NULL == btn_label && MAEMOSEC_CERTMAN_DOMAIN_PRIVATE == domain_flags)
		btn_label = _("cert_bd_c_delete");

    /* Put infobox in a scroller and add that to dialog */
    scroller = create_scroller(infobox);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroller),
                                   GTK_POLICY_AUTOMATIC,
                                   GTK_POLICY_AUTOMATIC);


    /* Put infobox scroller to right place */
	gtk_container_add(GTK_CONTAINER(GTK_DIALOG(cert_dialog)->vbox),
					  scroller);

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

	if (has_private_key(cert) && INSTALL_CERT > domain_flags) {
		change_password_button = gtk_dialog_add_button
            (GTK_DIALOG(cert_dialog),
             _("cert_bd_change_password"),
             GTK_RESPONSE_CHANGE_PASSWORD);
	}
		
	if (NULL != btn_label)
		bn_button = gtk_dialog_add_button(GTK_DIALOG(cert_dialog),
										  btn_label,
										  GTK_RESPONSE_APPLY);

    /* Show and run the dialog */
	MAEMOSEC_DEBUG(1, "Showing details");
    gtk_widget_show_all(cert_dialog);

    do {
        ret = gtk_dialog_run(GTK_DIALOG(cert_dialog));
        MAEMOSEC_DEBUG(1, "%s: gtk_dialog_run returned %d", __func__, ret);

        if (GTK_RESPONSE_APPLY == ret) {
			result = TRUE;
			break;

        } else if (GTK_RESPONSE_CHANGE_PASSWORD == ret) {
			EVP_PKEY* pkey;
			maemosec_key_id key_id;
			gchar* old_password = NULL;
			gchar* new_password = NULL;
			int rc;
            gchar *cert_name;
            
			rc = maemosec_certman_get_key_id(cert, key_id);
			if (0 != rc) {
				MAEMOSEC_ERROR("%s: cannot get key id (%d)", __func__, rc);
				continue;
			}

            cert_name = get_user_cert_name(cert);
            cert_name_for_get_privatekey = cert_name;
			pkey = certmanui_get_privatekey(window, key_id, &old_password, NULL, NULL);
            g_free(cert_name);
            cert_name_for_get_privatekey = NULL;

			/*
			 * We don't need this any more
			 */
            MAEMOSEC_DEBUG(1, "%s: got old password '%s'", __func__, old_password);
			if (old_password)
				g_free(old_password);
			if (NULL == pkey) {
				MAEMOSEC_ERROR("%s: wrong password obviously", __func__);
				continue;
			}
			/*
			 * Then ask for the new password
			 */
			new_password = get_new_password(window);
			if (NULL == new_password) {
				MAEMOSEC_ERROR("%s: cancelled obviously", __func__);
				EVP_PKEY_free(pkey);
				continue;
			}

			/*
			 * Store the key with the new password
			 */
            if (0 != strcmp(new_password, "")) {
                MAEMOSEC_DEBUG(1, "%s: store with new password '%s'", __func__, 
                               new_password);
                rc = maemosec_certman_store_key(key_id, pkey, new_password);
            } else {
                MAEMOSEC_DEBUG(1, "%s: store with default password '%s'", __func__, 
                               DEFAULT_PASSWORD);
                rc = maemosec_certman_store_key(key_id, pkey, DEFAULT_PASSWORD);
            }

			if (0 == rc) {
				/* TRANSLATE */
				// hildon_banner_show_information (window, NULL, "password changed");
			} else {
				MAEMOSEC_ERROR("%s: cannot store private key (%d)", __func__, rc);
				// hildon_banner_show_information (window, NULL, "password changing failed");
			}
            g_free(new_password);
		}
    } while (GTK_RESPONSE_DELETE_EVENT != ret);

    gtk_widget_hide_all(cert_dialog);

    /* Scroller is always destroyed */
    gtk_widget_destroy(scroller);
    scroller = NULL; 
	/* TODO: Infobox needs not to be destroyed? */
	infobox = NULL;

	gtk_widget_destroy(cert_dialog);
	// if (bn_button)
	// 	gtk_widget_destroy(bn_button);
    return(result);
}

gboolean 
certmanui_install_certificate_details_dialog(gpointer window, X509* cert)
{
	MAEMOSEC_DEBUG(1, "Called certmanui_install_certificate_details_dialog");
	return(_certificate_details(window, INSTALL_CERT, cert));
}


static int
get_fingerprint(X509 *of_cert, 
				EVP_MD** use_type, 
				char* label, 
				size_t label_size,
				char* value,
				size_t value_size)
{
	const EVP_MD* of_type;
	unsigned char digest_bin[MAX_DIGEST_LEN];
	size_t digest_len, i;
	char *digest_name, *hto;

	/*
	 * Just show the SHA1 fingerprint always-
	 */
	of_type = EVP_sha1();
	digest_name = "SHA1";
	MAEMOSEC_DEBUG(1, "Compute %s fingerprint", digest_name);
	*use_type = (EVP_MD*)of_type;

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


struct cb_info {
	GtkWidget* infobox;
	gint* row;
	char* label;
};

static void 
add_name_component(unsigned char* text, void* ctx)
{
	struct cb_info* lctx = (struct cb_info*)ctx;

	/*
	 * Do not add empty components.
	 */
	if (NULL != text && strlen((char*)text) && NULL != ctx) {
		MAEMOSEC_DEBUG(1, "Add name component '%s=%s'", lctx->label, text);
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


static int
X509_check_cert_time(X509* cert)
{
	time_t now = time(NULL);
	if (0 <= X509_cmp_time(X509_get_notBefore(cert), &now)) {
		MAEMOSEC_DEBUG(1, "Certificate is not yet valid");
		return(X509_V_ERR_CERT_NOT_YET_VALID);
	}
	if (0 >= X509_cmp_time(X509_get_notAfter(cert), &now)) {
		MAEMOSEC_DEBUG(1, "Certificate has expired");
		return(X509_V_ERR_CERT_HAS_EXPIRED);
	}
	return(0);
}


static void
show_certificate_error(gpointer window, int openssl_error)
{
	if (X509_V_ERR_CERT_NOT_YET_VALID == openssl_error
		|| X509_V_ERR_CERT_HAS_EXPIRED == openssl_error)
		hildon_banner_show_information(window, NULL, _("cert_nc_expired"));
	else
		hildon_banner_show_information(window, NULL, _("cert_error_install"));
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
	
	if (0 < X509_verify_cert(csc)) {
		*self_signed = 1;
	} else {
		*openssl_error = csc->error;
		MAEMOSEC_DEBUG(1, "Verification fails: %s", 
					   X509_verify_cert_error_string(csc->error));
		if (X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY == csc->error) {
			/*
			 * TODO: Is there a possibility that this would mask
			 * other errors. X509_check_cert_time returns 0 if
			 * the certificate is valide timewise.
			 */
			*openssl_error = X509_check_cert_time(cert);
		}
	}
	X509_STORE_CTX_free(csc);
	X509_STORE_free(tmp_store);
}


static GtkWidget* 
_create_infobox(gpointer window, X509* cert, gchar** btn_label)
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
		 * Handle openssl error
		 */
		if (0 != openssl_error) {
			MAEMOSEC_DEBUG(1, "Openssl error: %s", X509_verify_cert_error_string(openssl_error));
			*btn_label = NULL;
			show_certificate_error(window, openssl_error);
		}
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
		char fingerprint_label[NAMEBUF_LEN];
		char fingerprint_text [NAMEBUF_LEN];

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


static void 
_add_labels(GtkTable* table, 
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

    gtk_label_set_text(GTK_LABEL(value_label), value);
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


/* Implementation */

/* 
 * A global parameter for supplying the certificate
 * name for the get_privatekey dialog. A temporary
 * solution to be replaced by a new function when 
 * its status has been checked and the change sync'd.
 */

/*
 * TODO: Is the callback and cancel_privatekey ever used?
 */
gchar *cert_name_for_get_privatekey = "";

struct pkey_passwd {
    maemosec_key_id key_id;
    EVP_PKEY* pkey;
};

static int
test_pkey_password(void *data, const gchar* pwd)
{
    struct pkey_passwd *arg = (struct pkey_passwd*) data;
    int rc;

    MAEMOSEC_DEBUG(1, "%s: test password '%s'", __func__, pwd); 
    rc = maemosec_certman_retrieve_key(arg->key_id, &arg->pkey, (char*)pwd);
    MAEMOSEC_DEBUG(1, "%s: %s", __func__, rc?"failure":"success"); 
    return (0 == rc);
}


EVP_PKEY* 
certmanui_get_privatekey(gpointer window, 
						 maemosec_key_id cert_id,
						 gchar** password,
						 PrivateKeyResponseFunc callback,
						 gpointer user_data)
{
	char key_id_str [MAEMOSEC_KEY_ID_STR_LEN];
    const gchar* pwd = g_strdup(DEFAULT_PASSWORD);
    struct pkey_passwd pwd_param;
    gchar* info = NULL;

	maemosec_certman_key_id_to_str(cert_id, key_id_str, sizeof(key_id_str));
	MAEMOSEC_DEBUG(1, "%s: for %s'", __func__, key_id_str);

    memcpy(pwd_param.key_id, cert_id, MAEMOSEC_KEY_ID_LEN);
    pwd_param.pkey = NULL;
    if (test_pkey_password(&pwd_param, pwd)) {
        MAEMOSEC_DEBUG(1, "%s: No password %s", __func__, key_id_str);
        if (password)
            *password = g_strdup(pwd);
        if (callback)
            callback(cert_id, pwd_param.pkey, (gchar*)pwd, user_data);
        return(pwd_param.pkey);
    }

    g_free((gchar*)pwd);

    if (NULL == cert_name_for_get_privatekey 
        || 0 == strlen(cert_name_for_get_privatekey)) 
    {
        /*
         * Search for the corresponding certificate from user-domains
         */
        const struct pkcs12_target *tgt;
        gchar domain_name[NAMEBUF_LEN];

        MAEMOSEC_DEBUG(1, "%s: constructing name", __func__);

        for (tgt = pkcs12_targets; tgt->symbolic_name && NULL == info; tgt++) {
            domain_handle domh;
            int rc;
            X509* cert;

            snprintf(domain_name, sizeof(domain_name), USER_DOMAIN_FMT, tgt->domain_name);
            rc = maemosec_certman_open_domain(domain_name, 
                                              MAEMOSEC_CERTMAN_DOMAIN_PRIVATE,
                                              &domh);
            if (0 == rc) {
                rc = maemosec_certman_load_cert(domh, cert_id, &cert);
                if (0 == rc) {
                    info = get_user_cert_name(cert);
                    MAEMOSEC_DEBUG(1, "%s: name is '%s'", __func__, info);
                    X509_free(cert);
                    cert = NULL;
                }
                maemosec_certman_close_domain(domh);
            }
        }
    } else
        info = cert_name_for_get_privatekey;

    pwd = ask_password(window, TRUE, test_pkey_password, &pwd_param, info);

    if (callback && NULL != pwd)
        callback(cert_id, pwd_param.pkey, (gchar*)pwd, user_data);

    if (password)
        *password = (gchar*)pwd;
    else
        g_free((gchar*)pwd);

    if (info != cert_name_for_get_privatekey && info)
        g_free(info);

    return pwd_param.pkey;
}


/*
 * Does anyone use this?
 */
void 
certmanui_cancel_privatekey(void)
{
    ;
    /*
    if (enter_password_dialog != NULL)
    {
        gtk_dialog_response(GTK_DIALOG(enter_password_dialog),
                            GTK_RESPONSE_CANCEL);
    }
    */
}


static gboolean
certmanui_confirm(gpointer window, X509* cert, const char* title)
{
	GtkWidget* dialog = NULL;
	gchar* banner = NULL;
	char cert_name[NAMEBUF_LEN];
	gint i;

	if (cert && 0 == maemosec_certman_get_nickname(cert, cert_name, sizeof(cert_name))) {
		banner = g_strdup_printf(_(title), cert_name);
	}

	if (banner) {
		dialog = hildon_note_new_confirmation(window, banner);
		g_free(banner);
	} else
		dialog = hildon_note_new_confirmation(window, _(title));

	i = gtk_dialog_run(GTK_DIALOG(dialog));
	gtk_widget_destroy(GTK_WIDGET(dialog));
	if (GTK_RESPONSE_OK == i)
		return(TRUE);
	else
		return(FALSE);
}

static gboolean
timeout_close_dialog(gpointer* the_dialog)
{
	MAEMOSEC_DEBUG(1, "Entered %s", __func__);
	gtk_widget_hide_all((GtkWidget*)the_dialog);
	gtk_widget_destroy(GTK_WIDGET(the_dialog));
	return(FALSE);
}


static void
certmanui_info(gpointer window, GtkWidget* dialog, const char* text)
{
	guint rc;
	if (window)
		hildon_banner_show_information(window, NULL, _(text));
	else {
		hildon_banner_show_information((gpointer)dialog, NULL, _(text));
		rc = gtk_timeout_add(2000, (GtkFunction)timeout_close_dialog, dialog);
		gtk_dialog_run(GTK_DIALOG(dialog));
	}
}


/*
 * Convenience function for showing a certain type of certificate expired dialog
 * for server certificates (cert_id = 0 used by default if needed for backword 
 * compatibility and means that the certificate in question is remote)
 */

gboolean 
certmanui_certificate_expired_with_name
(
 gpointer window,
 CertmanUIExpiredDialogType type,
 const gchar* cert_name,
 CertificateExpiredResponseFunc callback,
 gpointer user_data
) {
    gint response_id = 0;
    GtkWidget* expired_dialog = NULL;
    GtkWidget* expired_label = NULL;

    static CallbackParameter params;

    if (cert_name == NULL) {
        /* 
		 * Here we assume that this function is called for already known
         * expired cert.. 
		 */
        if (callback != NULL) 
			callback(TRUE, user_data);
		MAEMOSEC_DEBUG(1, "%s: <null>", __func__);
		return(TRUE);
    }

	MAEMOSEC_DEBUG(1, "%s: %s", __func__, cert_name);

    expired_dialog = gtk_dialog_new_with_buttons
		(
		 _("cert_nc_expired"),
		 GTK_WINDOW(window),
		 GTK_DIALOG_DESTROY_WITH_PARENT
		 | GTK_DIALOG_NO_SEPARATOR,
		 NULL);

	/*
	 * Just show the name of the certificate 
	 * that does not work
	 */
	expired_label = gtk_label_new(cert_name);
    gtk_label_set_line_wrap(GTK_LABEL(expired_label), TRUE);
    gtk_container_add(GTK_CONTAINER(GTK_DIALOG(expired_dialog)->vbox),
                      expired_label);

    /* Add buttons to the dialog */
    gtk_dialog_add_button(GTK_DIALOG(expired_dialog),
                          dgettext("hildon-libs", "wdgt_bd_done"),
                          GTK_RESPONSE_OK);

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
            MAEMOSEC_DEBUG(1, "%s: gtk_dialog_run returned %d", __func__, response_id);
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
certmanui_show_error_with_name_and_serial
(
 gpointer window,
 CertmanUIErrorType type,
 const gchar* cert_name,
 const gchar* cert_serial,
 gpointer param,
 CertificateExpiredResponseFunc callback,
 gpointer user_data
) {
    GtkWidget* note = NULL;
    static CallbackParameter params;
    gchar* buf = NULL;

    if (cert_name == NULL && cert_serial == NULL)
    {
        MAEMOSEC_ERROR("No certificate name or serial supplied");
        if (callback != NULL) 
			callback(TRUE, user_data);
		MAEMOSEC_DEBUG(1, "%s: <null>", __func__);
        return(TRUE);
    }

	MAEMOSEC_DEBUG(1, "%s: %s", __func__, cert_name);

    /* Select string according to error type */
    switch(type)
		{
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

		default:
			buf = "";
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


static void 
_expired_dialog_response(GtkDialog* dialog,
						 gint response_id,
						 gpointer data)
{
    CallbackParameter* params = (CallbackParameter*)data;

    if (params == NULL)
    {
        MAEMOSEC_ERROR("No params for _expired_dialog_response!");
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


static void 
_infonote_dialog_response(GtkDialog* dialog,
						  gint response_id,
						  gpointer data)
{
    CallbackParameter* params = (CallbackParameter*)data;

    if (params == NULL)
    {
        MAEMOSEC_ERROR("_infonote_dialog_response: wrong parameters");
		return;
    }

    params->callback(TRUE, params->user_data);
    gtk_widget_destroy(GTK_WIDGET(dialog));
}


static void 
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
    GList* domains = NULL;
	maemosec_key_id cert_key;
	int rc, domain_flags;
	domain_handle dh = 0;
	X509 *cert = NULL;
	char* b64_cert = NULL;
    gboolean is_valid;

	MAEMOSEC_DEBUG(1, "Enter %s", __func__);

    /* Set iterator to point to right node */
    if (!gtk_tree_model_get_iter(model, &iter, path))
    {
		MAEMOSEC_ERROR("%s: cannot get iterator", __func__);
        return;
    }

    /* Get certificate ID */
    gtk_tree_model_get(model, &iter, 
					   MAIN_NAME_COL, &name_str, 
					   MAIN_ID_COL, &cert_id, 
					   MAIN_DOMAIN_COL, &domain,
					   MAIN_DOM_TYPE_COL, &domain_flags,
					   MAIN_CONTENT_COL, &b64_cert,
					   -1);

	window = gtk_widget_get_ancestor(GTK_WIDGET(tree), GTK_TYPE_WINDOW);

    if (NULL != domain) {
        _split_string(domain, ',', &domains);
        g_free(domain);
        domain = NULL;
    }

	if (NULL == b64_cert) {
        /*
         * Get the certificate from the first domain it exists in
         */
        gchar* first_domain = g_list_nth_data(domains, 0);

		MAEMOSEC_DEBUG(1, "%s: fetch %s:%s:%s:%s", __func__, 
					   MAEMOSEC_CERTMAN_DOMAIN_SHARED==domain_flags?"shared":"private",
					   first_domain, cert_id, name_str);

		rc = maemosec_certman_open_domain(first_domain, domain_flags, &dh);
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

	} else {
        /*
         * Get the certificate from the base64 encoded data (when installing)
         */
		unsigned len;
		unsigned char *cert_der = NULL;

		len = base64_decode(b64_cert, &cert_der);
		if (0 < len && NULL != cert_der) {
			const unsigned char* tmp = cert_der;
			MAEMOSEC_DEBUG(1, "%s: decoded %d bytes", __func__, len);
			cert = d2i_X509(NULL, &tmp, len);
			if (NULL == cert)
				MAEMOSEC_ERROR("Couldn't convert into a certificate");
		} else {
			MAEMOSEC_ERROR("%s: decoding failed", __func__);
		}
		if (cert_der)
			free(cert_der);
	}

    is_valid = (0 == X509_check_cert_time(cert));

    while (certmanui_certificate_details_dialog(window, domain_flags, cert)) {
        GList* tmp_domains = NULL;
        GtkWidget* ask_domains_dialog = NULL;
        gboolean doit = FALSE;
        char domain_name[NAMEBUF_LEN];
        GList *new_domains = NULL, *tmp = NULL,
            *add_to = NULL, *remove_from = NULL;
        gchar *help = NULL;

        if (is_valid) {
            tmp_domains = g_list_copy(domains);
            doit = ask_domains(window, &ask_domains_dialog, &tmp_domains);

            gtk_widget_hide_all(ask_domains_dialog);
            gtk_widget_destroy(ask_domains_dialog);

            if (!doit) {
                g_list_free(tmp_domains);
                tmp_domains = NULL;
                continue;
            }

            _join(tmp_domains, ",", &help);
            MAEMOSEC_DEBUG(1, "%s: tmp domains is '%s'", __func__, help);
            g_free(help);

            for (tmp = tmp_domains; tmp && tmp->data; tmp = tmp->next) {
                if (X509_check_ca(cert)) {
                    snprintf(domain_name, sizeof(domain_name),
                             CA_DOMAIN_FMT, (char*)tmp->data);
                } else {
                    snprintf(domain_name, sizeof(domain_name),
                             USER_DOMAIN_FMT, (char*)tmp->data);
                }
                new_domains = g_list_append(new_domains, g_strdup(domain_name));
            }

            _join(domains, ",", &help);
            MAEMOSEC_DEBUG(1, "%s: old domains is '%s'", __func__, help);
            g_free(help);

            _join(new_domains, ",", &help);
            MAEMOSEC_DEBUG(1, "%s: new domains is '%s'", __func__, help);
            g_free(help);

            /*
             * If removing from all domains, ask for confirmation
             */
            if (0 == g_list_length(new_domains)) {
                if (!certmanui_confirm(window, cert, "cert_nc_confirm_dialog")) {
                    g_list_free(new_domains);
                    new_domains = NULL;
                    continue;
                }
            }

            _list_difference(domains, new_domains, &remove_from);
            _join(remove_from, ",", &help);
            MAEMOSEC_DEBUG(1, "%s: remove from domains '%s'", __func__, help);
            g_free(help);

            _list_difference(new_domains, domains, &add_to);
            _join(add_to, ",", &help);
            MAEMOSEC_DEBUG(1, "%s: add to domains '%s'", __func__, help);
            g_free(help);

        } else {
            if (certmanui_confirm(window, cert, "cert_nc_confirm_dialog")) {
                remove_from = g_list_copy(domains);
            } else {
                continue;
            }
        }

        for (tmp = remove_from; tmp && tmp->data; tmp = tmp->next) {
            rc = maemosec_certman_open_domain(tmp->data, domain_flags, &dh);
            if (0 == rc) {
                rc = maemosec_certman_rm_cert(dh, cert_key);
                if (0 == rc)
                    MAEMOSEC_DEBUG(1, "%s: removed from domain  '%s'", __func__, tmp->data);
                maemosec_certman_close_domain(dh);
                dh = 0;
            }
        }

        for (tmp = add_to; tmp && tmp->data; tmp = tmp->next) {
            rc = maemosec_certman_open_domain(tmp->data, domain_flags, &dh);
            if (0 == rc) {
                rc = maemosec_certman_add_cert(dh, cert);
                if (0 == rc)
                    MAEMOSEC_DEBUG(1, "%s: added to domain  '%s'", __func__, tmp->data);
                maemosec_certman_close_domain(dh);
                dh = 0;
            }
        }

        g_list_free(domains);
        domains = g_list_copy(new_domains);

        if (0 == g_list_length(domains)) {
            /*
             * Certificate removed entirely
             */
            certmanui_info(window, NULL, "cert_ib_uninstalled");
            MAEMOSEC_DEBUG(1, "%s: certificate %s deleted", __func__, cert_id);
            if (gtk_list_store_remove(list_store, &iter)) {
                MAEMOSEC_DEBUG(1, "%s: gtk_list_store_remove returned TRUE", __func__);
                gtk_tree_model_row_deleted(model, path);
                break;
            } else
                MAEMOSEC_DEBUG(1, "gtk_list_store_remove returned FALSE");

        } else {
            /*
             * Update the domains and usage info in the main list
             * TODO: Remove redundancy with copy_search_tree 
             */
            gchar *new_domains_str, *new_usage_str;
            GList *new_usages = NULL;
            char cert_name [NAMEBUF_LEN];
	
            maemosec_certman_get_nickname(cert, cert_name, sizeof(cert_name));

            _join(domains, ",", &new_domains_str);
            for (tmp = domains; tmp && tmp->data; tmp = tmp->next) {
                new_usages = g_list_append(new_usages, g_strdup(get_purpose_name(tmp->data)));
            }
            _join(new_usages, ", ", &new_usage_str);

            MAEMOSEC_DEBUG(1, "%s: %s new usage %s", __func__, cert_name, new_usage_str);

            gtk_list_store_set(list_store, &iter, 
                               MAIN_NAME_COL, 
                               _cert_item_label(TRUE, cert_name, new_usage_str),
                               MAIN_DOMAIN_COL, new_domains_str,
                               -1);

            gtk_tree_model_row_changed(model, path, &iter);
            g_list_free(new_usages);
            g_free(new_usage_str);
        }

        g_list_free(remove_from);
        remove_from = NULL;
        g_list_free(add_to);
        add_to = NULL;
        g_list_free(new_domains);
        new_domains = NULL;
        g_list_free(tmp_domains);
        tmp_domains = NULL;
    } // while

 end:
    if (domains)
        g_list_free(domains);
	if (dh)
		maemosec_certman_close_domain(dh);
	if (cert)
		X509_free(cert);
	if (b64_cert)
		g_free(b64_cert);
	if (name_str)
		g_free(name_str);
	if (cert_id)
		g_free(cert_id);
	return;
}


static void
_import_certificate(GtkAction *action, struct import_context *ctx)
{        
    ComappOpenSave opensave_data;
    comapp_fc_result select_result;
    gchar *filename = NULL;

    memset(&opensave_data,0,sizeof(ComappOpenSave));
    
    opensave_data.action = GTK_FILE_CHOOSER_ACTION_OPEN;
    opensave_data.parent = gtk_widget_get_ancestor(GTK_WIDGET(ctx->tree), GTK_TYPE_WINDOW);
    opensave_data.open_window_title = _("cert_ti_main_notebook_import");
    opensave_data.osso = osso_global;
    opensave_data.mime_types = cert_mimetypes; 

    comapp_opensave_new(&opensave_data);
    select_result = comapp_opensave_run(&opensave_data);
    if (COMAPP_FILE_CHOOSER_SELECTED == select_result) {
        filename = opensave_data.result_uri;
        MAEMOSEC_DEBUG(1, "%s: import a new certificate from '%s'", __func__, filename);
        if (certmanui_import_file(ctx->window, filename, NULL, NULL)) {
            gtk_list_store_clear(ctx->list_store);
            _populate_all_certificates(ctx->list_store);
        }
    }
    g_free(opensave_data.result_uri);
}


int
report_openssl_error(const char* str, size_t len, void* u)
{
	char* tmp = strrchr(str, '\n');
	if (tmp && ((tmp - str) == strlen(str)))
		*tmp = '\0';
	MAEMOSEC_DEBUG(1, "OpenSSL error '%s'", str);
	ERR_clear_error();
	return(0);
}


#define MAX_RETRIES 10

const gchar*
ask_password(gpointer window, 
             gboolean object_is_cert,
			 int test_password(void* data, const gchar* pwd), 
			 void* data, 
			 const char* info)
{
	HildonGetPasswordDialog* password_dialog = NULL;
	gint response = 0;
	const gchar *result;

    /*
     * Use generic hildon_get_password_dialog.
     */
	MAEMOSEC_DEBUG(1, "%s: Enter", __func__);
	password_dialog = HILDON_GET_PASSWORD_DIALOG(hildon_get_password_dialog_new(window, FALSE));
    if (object_is_cert) {
        gtk_window_set_title(GTK_WINDOW(password_dialog), _("cert_ti_enter_password"));
        hildon_get_password_dialog_set_message(password_dialog, info);
    } else {
        gtk_window_set_title(GTK_WINDOW(password_dialog), _("cert_ti_enter_file_password"));
        hildon_get_password_dialog_set_message
            (password_dialog, g_strdup_printf(_("cert_ia_explain_file_password"), info));
    }
    // hildon_get_password_dialog_set_max_characater(password_dialog, 100);
	gtk_widget_show_all(GTK_WIDGET(password_dialog));
    do {
        response = gtk_dialog_run(GTK_DIALOG(password_dialog));
        MAEMOSEC_DEBUG(1, "%s: gtk_dialog_run returned %d", __func__, response);
        if (GTK_RESPONSE_OK == response) {
            result = g_strdup(hildon_get_password_dialog_get_password(password_dialog));
            if (!test_password(data, result)) {
                g_object_set(G_OBJECT(password_dialog), "password", "", NULL);
				hildon_banner_show_information(GTK_WIDGET(password_dialog), 
											   NULL, 
											   _("cer_ib_incorrect"));
                g_free((void*)result);
                result = NULL;
            } else
                break;
        }
    } while (GTK_RESPONSE_DELETE_EVENT != response);
    
	gtk_widget_hide_all(GTK_WIDGET(password_dialog));
	gtk_widget_destroy(GTK_WIDGET(password_dialog));

    return(result);
}


static gboolean
certmanui_install_certificates_dialog(gpointer window, 
									  STACK_OF(X509) *certs,
									  EVP_PKEY* pkey)
{
	GtkWidget* install_dialog = NULL;
	GtkListStore* contents_store = NULL;
	GtkWidget* contents_list = NULL;
	GtkWidget *panarea = NULL;
	GtkWidget *bn_install = NULL;
    GtkTreeIter iter;
	GdkGeometry hints;
	char namebuf[NAMEBUF_LEN];
	int i, rc, g_openssl_error = 0;
	gint ret;
	gboolean result = FALSE;
	const gchar *cert_type;

	MAEMOSEC_DEBUG(1, "Enter %s", __func__);

	install_dialog = gtk_dialog_new_with_buttons
		(_("cert_ti_install_certificates"),
		 GTK_WINDOW(window),
		 GTK_DIALOG_DESTROY_WITH_PARENT
		 | GTK_DIALOG_NO_SEPARATOR,
		 NULL);

    hints.min_width  = MIN_WIDTH;
    hints.min_height = MIN_HEIGHT;
    hints.max_width  = MAX_WIDTH;
    hints.max_height = MAX_HEIGHT;

	gtk_window_set_geometry_hints(GTK_WINDOW(install_dialog), 
								  install_dialog, 
								  &hints,
                                  GDK_HINT_MIN_SIZE | GDK_HINT_MAX_SIZE);

	_create_certificate_list(&contents_list, &contents_store);

	panarea = hildon_pannable_area_new();
	gtk_container_add(GTK_CONTAINER(panarea), contents_list);

    g_signal_connect(G_OBJECT(contents_list), 
					 "row-activated",
                     G_CALLBACK(cert_list_row_activated),
                     contents_store);

	for (i = 0; i < sk_X509_num(certs); i++) {

		X509* cert = sk_X509_value(certs, i);
		unsigned char* cder;
		char* b64cert;
		maemosec_key_id key_id;
		char key_id_str [MAEMOSEC_KEY_ID_STR_LEN];
		int len;

		rc = maemosec_certman_get_nickname(cert, namebuf, sizeof(namebuf));
		MAEMOSEC_DEBUG(1, "Certificate '%s' (%d)", namebuf, rc);
		if (0 != rc) {
			MAEMOSEC_ERROR("Failed to get nickname");
			continue;
		}

		{
			int self_signed;
			int openssl_error = 0;
			check_certificate(cert, &self_signed, &openssl_error);
			if (0 != openssl_error) {
				if (0 == g_openssl_error)
					g_openssl_error = openssl_error;
				MAEMOSEC_ERROR("%s: '%s' : %s", __func__, namebuf, 
							   X509_verify_cert_error_string(openssl_error));
			}
		}

		cder = NULL;
		len = i2d_X509(cert, &cder);
		
		if (0 > len || NULL == cder) {
			MAEMOSEC_ERROR("Failed to convert '%s' to DER", namebuf);
			continue;
		}

		b64cert = base64_encode(cder, len);
		MAEMOSEC_DEBUG(1, "%s: encoded %d bytes", __func__, len);

		gtk_list_store_append(contents_store, &iter);
		gtk_list_store_set(contents_store, &iter, 
						   MAIN_CONTENT_COL, b64cert, 
						   MAIN_DOM_TYPE_COL, INSTALL_CERT + 1,
						   -1);

		if (   0 == maemosec_certman_get_key_id(cert, key_id)
			&& 0 == maemosec_certman_key_id_to_str(key_id, key_id_str, sizeof(key_id_str)))
				gtk_list_store_set(contents_store, &iter, MAIN_ID_COL, key_id_str, -1);

        /*
         * TODO: The certificate type is not shown at all
         */
        if (X509_check_ca(cert)) {
            cert_type = "cert_li_certificate_signing";
        } else if (NULL != pkey) {
            cert_type = "cert_li_certificate_user";
        } else {
            cert_type = "cert_li_certificate_user";
        }
        gtk_list_store_set(contents_store, &iter, 
						   MAIN_NAME_COL, namebuf,
						   -1);
		free(b64cert);
		OPENSSL_free(cder);
	}
	
	if (0 == g_openssl_error) {
		bn_install = gtk_dialog_add_button(GTK_DIALOG(install_dialog),
										   _("cert_bd_cd_install"), 
										   GTK_RESPONSE_APPLY);
	} else {
		show_certificate_error(window, g_openssl_error);
	}

	MAEMOSEC_DEBUG(1, "Add pan area");
    gtk_container_add(GTK_CONTAINER(GTK_DIALOG(install_dialog)->vbox), panarea);

	MAEMOSEC_DEBUG(1, "Show all");
    gtk_widget_show_all(install_dialog);

	do {
        ret = gtk_dialog_run(GTK_DIALOG(install_dialog));
        MAEMOSEC_DEBUG(1, "%s: gtk_dialog_run returned %d", __func__, ret);

        if (GTK_RESPONSE_APPLY == ret) {
			MAEMOSEC_DEBUG(1, "%s: Install!", __func__);
			result = TRUE;
			break;
        }
	} while (GTK_RESPONSE_DELETE_EVENT != ret);

    gtk_widget_hide_all(install_dialog);

	gtk_widget_destroy(install_dialog);
	if (bn_install)
		gtk_widget_destroy(bn_install);

	return(result);
}


static gboolean
ask_domains(gpointer window, 
			GtkWidget **dialog,
			GList** domains)
{
    gboolean had_previous = FALSE;
	gint response, pos;
	HildonTouchSelector *selector;
	GdkGeometry hints;
	GtkWidget* panarea;
	GtkWidget* bn_button;
	GList *selected = NULL;
	const struct pkcs12_target *tgt;

	MAEMOSEC_DEBUG(1, "Enter %s", __func__);
	
	*dialog = gtk_dialog_new_with_buttons(_("cert_ti_application_trust"),
                                          GTK_WINDOW(window),
                                          GTK_DIALOG_DESTROY_WITH_PARENT
                                          | GTK_DIALOG_NO_SEPARATOR,
										 NULL);
    hints.min_width  = MIN_WIDTH;
    hints.min_height = MIN_HEIGHT + 100;
    hints.max_width  = MAX_WIDTH;
    hints.max_height = MAX_HEIGHT + 100;

	gtk_window_set_geometry_hints(GTK_WINDOW(*dialog), *dialog, &hints,
                                  GDK_HINT_MIN_SIZE | GDK_HINT_MAX_SIZE);

    if (*domains && 0 != strcmp("*", (*domains)->data)) {
        bn_button = gtk_dialog_add_button(GTK_DIALOG(*dialog),
                                          _("cert_bd_c_delete"),
                                          GTK_RESPONSE_RM_CERTIFICATE);
    }

	bn_button = gtk_dialog_add_button(GTK_DIALOG(*dialog),
									  _("cert_bd_trust_settings_ok"),
									  GTK_RESPONSE_APPLY);

	selector = (HildonTouchSelector*)hildon_touch_selector_new_text();
	hildon_touch_selector_set_column_selection_mode
		(selector, HILDON_TOUCH_SELECTOR_SELECTION_MODE_MULTIPLE);

    pos = -1;
	for (tgt = pkcs12_targets; tgt->symbolic_name; tgt++) {
        GList* tmp;
		hildon_touch_selector_append_text(selector, _(tgt->symbolic_name));
        pos++;
        if (*domains) {
            for (tmp = *domains; tmp && tmp->data; tmp = tmp->next) {
                MAEMOSEC_DEBUG(1, "%s: check if '%s' matches '%s'", __func__,
                               tgt->domain_name, tmp->data);
                if (0 == memcmp(tgt->domain_name, tmp->data, strlen(tgt->domain_name))
                    || 0 == strcmp("*", tmp->data)) 
                {
                    GtkTreePath* path;
                    GtkTreeIter iter;
                    MAEMOSEC_DEBUG(1, "%s: it does, activate %d", __func__, pos);
                    path = gtk_tree_path_new_from_indices(pos, -1);
                    if (path) {
                        if (gtk_tree_model_get_iter(hildon_touch_selector_get_model(selector, 0),
                                                    &iter, path))
                            hildon_touch_selector_select_iter(selector, 0, &iter, FALSE);
                        gtk_tree_path_free(path);
                    }
                    break;
                }
            }
        }
    }

	panarea = hildon_pannable_area_new();
	gtk_container_add(GTK_CONTAINER(panarea), (GtkWidget*)(selector));

	gtk_widget_set_size_request(GTK_WIDGET(panarea), 0, 0);
    gtk_container_add(GTK_CONTAINER(GTK_DIALOG(*dialog)->vbox), panarea);

	gtk_widget_show_all(*dialog);

    response = gtk_dialog_run(GTK_DIALOG(*dialog));
	MAEMOSEC_DEBUG(1, "%s: gtk_dialog_run returned %d", __func__, response);

    if (*domains) {
        had_previous = TRUE;
        g_list_free(*domains);
        *domains = NULL;
    }

    if (GTK_RESPONSE_APPLY == response) {
        selected = hildon_touch_selector_get_selected_rows(selector, 0);
        while (selected) {
            GtkTreePath *sel = (GtkTreePath*)(selected->data);
            gchar* domain_name = pkcs12_targets[*gtk_tree_path_get_indices(sel)].domain_name;
            MAEMOSEC_DEBUG(1, "%s: selected '%s'", __func__, domain_name);
            *domains = g_list_append(*domains, g_strdup(domain_name));
            selected = selected->next;
        }
        g_list_free(selected);
    }

	MAEMOSEC_DEBUG(1, "Exit %s", __func__);

	return((GTK_RESPONSE_APPLY == response || GTK_RESPONSE_RM_CERTIFICATE == response)
           && (0 < g_list_length(*domains) || had_previous));
}


gboolean 
certmanui_import_file(gpointer window, 
					  const gchar* fileuri,
					  maemosec_key_id* cert_id, 
					  GSList **pk12_list)
{
	STACK_OF(X509) *certs = NULL;
	EVP_PKEY *pkey = NULL;
	GtkWidget *dialog = NULL;
	GList* domains = NULL;
	const char *confirmation_text;
	gchar* password = NULL;
	bool do_install;

	if (!extract_envelope(window, fileuri, &certs, &pkey, &password)) {
		if (NULL == password)
			MAEMOSEC_ERROR("Invalid certificate file '%s'", fileuri);
		return(FALSE);
	}

	if (NULL == pkey && 1 == sk_X509_num(certs)) {
		/*
		 * Just a single certificate
		 */
		do_install = certmanui_install_certificate_details_dialog
			(window, sk_X509_value(certs, 0));
		MAEMOSEC_DEBUG(1, "certmanui_install_certificate_details_dialog=%d", 
					   do_install);
		confirmation_text = "cert_ib_installed_certificate";
	} else {
		/* 
		 * A packet of many certificates or a user-cert+private key
		 * combo.
		 */
		do_install = certmanui_install_certificates_dialog
			(window, certs, pkey);
		MAEMOSEC_DEBUG(1, "certmanui_install_certificates_dialog=%d", 
					   do_install);
		if (1 == sk_X509_num(certs))
			confirmation_text = "cert_ib_installed_certificate";
		else
			confirmation_text = "cert_ib_installed_certificates";
	}

	if (!do_install)
		goto cleanup;

	MAEMOSEC_DEBUG(1, "Ask purpose");

    /*
     * Enable all uses by default
     */
    domains = g_list_append(NULL, "*");
	do_install = ask_domains(window, &dialog, &domains);
		
	if (!do_install) 
		goto cleanup;

	MAEMOSEC_DEBUG(1, "About to install");
	while (domains) {
		char domain_name[NAMEBUF_LEN];
		char cert_name[NAMEBUF_LEN];
		domain_handle dh;
		int i, rc;

		for (i = 0; i < sk_X509_num(certs); i++) {
			X509* cert = sk_X509_value(certs, i);
			rc = maemosec_certman_get_nickname(cert, cert_name, sizeof(cert_name));
			if (X509_check_ca(cert)) {
				snprintf(domain_name, sizeof(domain_name),
						 CA_DOMAIN_FMT, (char*)domains->data);
			} else {
				snprintf(domain_name, sizeof(domain_name),
						 USER_DOMAIN_FMT, (char*)domains->data);
				if (pkey) {
					maemosec_key_id key_id;
					rc = maemosec_certman_get_key_id(cert, key_id);
					if (0 == rc) {
						rc = maemosec_certman_store_key(key_id, pkey, 
                                                        password?password:DEFAULT_PASSWORD);
						if (0 == rc)
							MAEMOSEC_DEBUG(1, "Stored private key");
						else
							MAEMOSEC_ERROR("Cannot store private key, rc = %d", rc);
					} else
						MAEMOSEC_ERROR("Cannot get key id, rc = %d", rc);
				} else {
					MAEMOSEC_DEBUG(1, "User cert '%s' without private key?",
								   cert_name);
				}
			}
			MAEMOSEC_DEBUG(1, "Installing '%s' to '%s'", cert_name, domain_name);

			rc = maemosec_certman_open_domain
				(domain_name, MAEMOSEC_CERTMAN_DOMAIN_PRIVATE, &dh);

			if (0 == rc) {
				rc = maemosec_certman_add_cert(dh, cert);
				if (EEXIST == rc) {
					/*
					 * Certificate already exists in the domain
					 */
					MAEMOSEC_ERROR("'%s' already exists in domain '%s'",
								   cert_name, domain_name);
				} else if (0 != rc) {
					/*
					 * Some other error
					 */
					MAEMOSEC_ERROR("cannot add '%s' to domain '%s', rc = %d",
								   cert_name, domain_name, rc);
				}
				maemosec_certman_close_domain(dh);
			} else {
				MAEMOSEC_ERROR("cannot open domain '%s', rc = %d",
							   domain_name, rc);
			}
		}
		domains = domains->next;
	}
	certmanui_info(NULL, dialog, confirmation_text);
	gtk_widget_hide_all(dialog);
	gtk_widget_destroy(dialog);

 cleanup:
	if (domains)
		g_list_free(domains);
	if (pkey)
		EVP_PKEY_free(pkey);
	if (certs)
		sk_X509_free(certs);
	return(TRUE);
}


static int
_split_string(gchar* string, gchar separator, GList** to_list)
{
    gchar *start, *end;

    if (NULL == string)
        return 0;

    start = string;
    while (*start) {
        end = strchr(start, separator);
        if (end) {
            *end = '\0';
            *to_list = g_list_append(*to_list, g_strdup(start));
            start = end + 1;
            *end = separator;
        } else {
            *to_list = g_list_append(*to_list, g_strdup(start));
            break;
        }
    }
    return g_list_length(*to_list);
}


static int
_list_difference(GList* in_this, GList* but_not_in_this, GList** copy_here)
{
    if (NULL == copy_here)
        return 0;
    for (; in_this && in_this->data; in_this = in_this->next) {
        gboolean found = FALSE;
        GList* tmp = NULL;
        for (tmp = but_not_in_this; tmp && tmp->data; tmp = tmp->next) {
            if (0 == strcmp(in_this->data, tmp->data)) {
                found = TRUE;
                break;
            }
        }
        if (!found) {
            *copy_here = g_list_append(*copy_here, g_strdup(in_this->data));
        }
    }
    return g_list_length(*copy_here);
}


static void
_join(GList* the_list, gchar* with_separator, gchar** to_string)
{
    gchar** str_array;
    int pos = 0;

    if (NULL == the_list) {
        *to_string = g_strdup("");
        return;
    }
    str_array = (gchar**)malloc((1 + g_list_length(the_list)) * sizeof(gchar*));
    for (; the_list && the_list->data; the_list = the_list->next) {
        str_array[pos++] = the_list->data;
    }
    str_array[pos] = NULL;
    *to_string = g_strjoinv(with_separator, str_array);
    free(str_array);
}
