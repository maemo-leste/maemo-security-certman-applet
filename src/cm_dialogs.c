/* -*- mode:c; tab-width:4; c-basic-offset:4; -*- */

#include "cm_dialogs.h"

#define _BSD_SOURCE
#define _XOPEN_SOURCE
#define _USE_POSIX

#include <libosso.h>
// #include <osso-log.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include <gtk/gtk.h>
#include <gdk/gdkkeysyms.h>

// #include <gtk/gtkenums.h>
// #include <hildon/hildon-gtk.h>
// #include <hildon/hildon-touch-selector.h>

#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <maemosec_common.h>
#include <maemosec_certman.h>

#include "i18n.h"
#include "osso-applet-certman.h"
#include "cm_envelopes.h"

/* Certificate list colums */
enum {
    MAIN_NAME_COL = 0,
    MAIN_PURPOSE_COL,
    MAIN_ID_COL,
    MAIN_DOMAIN_COL,
    MAIN_DOM_TYPE_COL,
    MAIN_CONTENT_COL,
    MAIN_NUM_COLUMNS
};

/* Local interface */

static void 
_create_certificate_list(GtkWidget** scroller,
						 GtkWidget** list,
						 GtkListStore** list_store);

struct populate_context {
	int domain_flags;
	gchar *title;
	GtkListStore *store;
};

static int 
_populate_certificates(int pos,
					   void* from_name,
					   void* ctx);

static void
_add_row_header(GtkListStore *list_store,
				const gchar* header_text);

static void _expired_dialog_response(GtkDialog* dialog,
                                     gint response_id,
                                     gpointer data);

static void _infonote_dialog_response(GtkDialog* dialog,
                                      gint response_id,
                                      gpointer data);
static void 
cert_list_row_activated(GtkTreeView* tree,
						GtkTreePath* path,
						GtkTreeViewColumn* col,
						gpointer user_data);

typedef enum {
    FALSE_CALLED, CANCEL_CALLED, OK_CALLED
} CbCalledResult;

typedef struct {
    CertificateExpiredResponseFunc callback;
    gpointer user_data;
} CallbackParameter;

/** Callback parameter for password query dialog response */
typedef struct {
    EVP_PKEY* got_key;
    maemosec_key_id cert_id;
    PrivateKeyResponseFunc callback;
    GtkWidget* passwd_entry;
    gpointer user_data;
} PwdCallbackParameter;


typedef struct {
    gpointer window;
    gchar* passwd; /* must be freed */
    X509* cert;
    CbCalledResult callback_called;
} PasswordCallbackParameter;

/** Callback parameter for password query dialog response */
typedef struct {
    EVP_PKEY* got_key;
    maemosec_key_id cert_id;
    PrivateKeyResponseFunc callback;
    GtkWidget* passwd_entry;
    gpointer user_data;
} PwdQCallbackParameter;


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



/* Implementation */
/*
 * TODO: Get rid of global variables
 */

GtkWidget* cert_list = NULL;
GtkListStore* cert_list_store = NULL;
GtkWidget* cert_scroller = NULL;
osso_context_t *osso_global;
GtkWindow* g_window = NULL;
static int flip_flop = 0;

/** Parameter for row_activated callback */
typedef struct {
	GtkTreeView* view;
	GtkListStore* list;
	GtkTreeIter iter;
	gboolean iter_valid;
	AuthType type;
	GtkWidget* view_button;
	GtkWidget* import_button;
	GtkWidget* export_button;
} RowParameter;

/** Parameter for some of the button callbacks */
typedef struct {
	RowParameter* rows;
	GtkNotebook* notebook;
	gpointer dialog;
	gpointer data;
} ButtonParameter;

/** Parameters for the row-activated callbacks */
typedef struct {
	gint id_col;
	gboolean simple;
} RowActivatedParameter;

/* Other globals */
GdkGeometry hints;
RowParameter row_params[2];
ButtonParameter button_param;

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
	{
		.symbolic_name = "cert_nc_purpose_software_signing", 
		.domain_name = "ssign"
	},
	{
		.symbolic_name = NULL,
		.domain_name = NULL
	}
};

static GtkWidget* 
create_password_dialog(gpointer window,
					   X509* cert,
					   const gchar* title,
					   const gchar* greeting,
					   const gchar* label,
					   const gchar* ok_label,
					   const gchar* cancel_label,
					   GtkWidget** passwd_entry,
					   gboolean install_timeout,
					   guint min_chars);

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
	const struct pkcs12_target *tgt;
	char domain_name[256];
	struct populate_context pc;
	int rc;

	MAEMOSEC_DEBUG(1, "Enter %s", __func__);

    if (window == NULL)
    {
		MAEMOSEC_DEBUG(1, "%s: NULL window, exit", __func__);
        return NULL;
    }
	g_window = window;

    /* Create dialog and set its attributes */
    main_dialog = gtk_dialog_new_with_buttons(_("cema_ap_application_title"),
                                         GTK_WINDOW(window),
                                         GTK_DIALOG_MODAL
                                         | GTK_DIALOG_DESTROY_WITH_PARENT
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

    _create_certificate_list(&cert_scroller,
                             &cert_list,
                             &cert_list_store);
	MAEMOSEC_DEBUG(1, "Created certificate lists");

	GtkWidget *panarea = hildon_pannable_area_new();
	hildon_pannable_area_add_with_viewport(HILDON_PANNABLE_AREA(panarea),
										  GTK_WIDGET(cert_list));
    g_signal_connect(G_OBJECT(cert_list), 
					 "row-activated",
                     G_CALLBACK(cert_list_row_activated),
                     cert_list_store);

	MAEMOSEC_DEBUG(1, "Populate user certificates");
	pc.store = cert_list_store;
	pc.domain_flags = MAEMOSEC_CERTMAN_DOMAIN_PRIVATE;
	pc.title = "cert_ti_main_notebook_user";
	for (tgt = pkcs12_targets; tgt->symbolic_name; tgt++) {
		snprintf(domain_name, sizeof(domain_name), USER_DOMAIN_FMT, tgt->domain_name);
		_populate_certificates(0, domain_name, &pc);
	}

	MAEMOSEC_DEBUG(1, "Populate user modifiable CA certificates");
	pc.title = "cert_ti_main_notebook_authorities";
	for (tgt = pkcs12_targets; tgt->symbolic_name; tgt++) {
		snprintf(domain_name, sizeof(domain_name), CA_DOMAIN_FMT, tgt->domain_name);
		_populate_certificates(0, domain_name, &pc);
	}

	MAEMOSEC_DEBUG(1, "Populate root CA certificates");
	pc.domain_flags = MAEMOSEC_CERTMAN_DOMAIN_SHARED;
	rc = maemosec_certman_iterate_domains(MAEMOSEC_CERTMAN_DOMAIN_SHARED,
										  _populate_certificates,
										  &pc);

	MAEMOSEC_DEBUG(1, "Add pan area");
    gtk_container_add(GTK_CONTAINER(GTK_DIALOG(main_dialog)->vbox), panarea);

	MAEMOSEC_DEBUG(1, "Show all");
	gtk_widget_show_all(main_dialog);

    return(main_dialog);
}

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

const int sortname_nids [] = {
	NID_organizationName,
	NID_organizationalUnitName,
	NID_commonName
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
								 sortname_add_name_component,
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
_populate_certificates(int pos, void* domain_name, void* ctx)
{
    GtkTreeIter iter;
    int rc;
	domain_handle my_domain;
	struct populate_context *pc = (struct populate_context*)ctx;
	struct cert_display_info cd_info;

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

	cd_info.domain_name = (char*)domain_name;
	cd_info.domain_type = pc->domain_flags;
	cd_info.store = pc->store;
	cd_info.iter = &iter;
	cd_info.search_tree = NULL;

	rc = maemosec_certman_iterate_certs(my_domain, fill_cert_data, &cd_info);
	maemosec_certman_close_domain(my_domain);

	/*
	 * TODO: order newly appended certificate records
	 */
	if (cd_info.search_tree) {
		/*
		 * Add header only if there are certificates and only once
		 */
		if (NULL != pc->title) {
			_add_row_header(pc->store, _(pc->title));
			pc->title = NULL;
		}

		_copy_search_tree(cd_info.search_tree, &cd_info);
		_release_search_tree(cd_info.search_tree);
	}
	/*
	 * Continue iteration even if there are invalid domains.
	 */
	return(0);
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
	int* flip_flop = (int*)data;

	gtk_tree_model_get(model, iter, 
					   MAIN_NAME_COL, &title, 
					   MAIN_ID_COL, &key_str, -1);

	if (NULL == key_str) {
		if (NULL != title) {
			MAEMOSEC_DEBUG(4, "%s: '%s' is row header, already set=%d", 
						   __func__, title, *flip_flop);
			if (header_text) {
				if (0 == *flip_flop) {
					*header_text = g_strdup(title);
					*flip_flop = 1;
				} else
					*header_text = g_strdup("");
			} else {
				*flip_flop = 0;
			}
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
					   MAIN_NAME_COL, header_text, 
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
        "text", 
		 MAIN_NAME_COL,
		 NULL);

    gtk_tree_view_column_set_widget(column, NULL);
    gtk_tree_view_append_column (GTK_TREE_VIEW(*list), column);
	hildon_tree_view_set_row_header_func(GTK_TREE_VIEW(*list), 
										 _is_row_header, &flip_flop, NULL);

#if 0
    g_object_set(G_OBJECT(column), "fixed-width", NAME_COL_WIDTH,
                 "sizing", GTK_TREE_VIEW_COLUMN_FIXED, NULL);
#endif

    /* Certificate purpose column */
	column = gtk_tree_view_column_new_with_attributes 
		(NULL,
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

    gtk_tree_view_set_headers_visible(GTK_TREE_VIEW(*list), FALSE);

    return;
}

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
    GtkWidget* cert_notebook = NULL;
    GtkWidget* cert_main_page = NULL;
	GtkWidget *bn_button = NULL;

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

    /* Check if cert_dialog != NULL */
	MAEMOSEC_DEBUG(1, "%s: show simple dialog", __func__);

	if (MAEMOSEC_CERTMAN_DOMAIN_PRIVATE == domain_flags) {
		dlg_title = _("cert_ti_viewing_dialog");
		btn_label = _("cert_bd_c_delete");

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

	if (cert_dialog == NULL) {
		cert_dialog = gtk_dialog_new_with_buttons
			(
			 dlg_title,
			 GTK_WINDOW(window),
			 GTK_DIALOG_MODAL
			 | GTK_DIALOG_DESTROY_WITH_PARENT
			 | GTK_DIALOG_NO_SEPARATOR,
			 NULL
			 );

		if (cert_dialog == NULL) {
			MAEMOSEC_ERROR("Failed to create dialog");
			return(FALSE);
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

	if (NULL != btn_label)
		bn_button = gtk_dialog_add_button(GTK_DIALOG(cert_dialog),
										  btn_label,
										  GTK_RESPONSE_APPLY);
		
    /* Show and run the dialog */
	MAEMOSEC_DEBUG(1, "Showing details");
    gtk_widget_show_all(cert_dialog);

    if (cert_notebook)
    {
        gtk_widget_grab_focus(cert_notebook);
    }

    do {
        MAEMOSEC_DEBUG(1, "Before gtk_dialog_run");
        ret = gtk_dialog_run(GTK_DIALOG(cert_dialog));
        MAEMOSEC_DEBUG(1, "After gtk_dialog_run=%d", ret);

        if (GTK_RESPONSE_APPLY == ret) {
			result = TRUE;
			break;
        }
    } while (GTK_RESPONSE_DELETE_EVENT != ret);

    gtk_widget_hide_all(cert_dialog);

    /* Scroller is always destroyed */
    gtk_widget_destroy(scroller);
    scroller = NULL; 
	/* TODO: Infobox needs not to be destroyed? */
	infobox = NULL;

    /* Save store and delete dialog, if they weren't initialized */

	gtk_widget_destroy(cert_dialog);
	if (bn_button)
		gtk_widget_destroy(bn_button);
    return(result);
}

gboolean 
certmanui_install_certificate_details_dialog(gpointer window,
											 X509* cert)
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
	unsigned char digest_bin[64];
	size_t digest_len, i;
	char *digest_name, *hto;

	/*
	 * DEBUG: Warn about MD5-based signatures
	 */
	if (of_cert && of_cert->sig_alg && of_cert->sig_alg->algorithm) {
		i2t_ASN1_OBJECT((char*)digest_bin, 
						sizeof(digest_bin), 
						of_cert->sig_alg->algorithm);
		digest_bin[sizeof(digest_bin)-1] = '\0';
		MAEMOSEC_DEBUG(1, "signed by %s", digest_bin);
		for (hto = (char*)digest_bin; *hto; hto++)
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


static const int fullname_components [] = {
		NID_commonName, NID_organizationalUnitName, NID_organizationName
};

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

    static PwdCallbackParameter params;

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
                                                 dgettext("hildon-libs", "wdgt_bd_done"),
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
    PwdCallbackParameter* params = (PwdCallbackParameter*)data;
    gchar* passwd = NULL;
	int rc;

    if (params == NULL)
    {
        MAEMOSEC_ERROR("No params for _password_dialog_response!");
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
certmanui_confirm(gpointer window, X509* cert, const char* title)
{
	GtkWidget* dialog = NULL;
	gchar* banner = NULL;
	char cert_name[256];
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
		 GTK_DIALOG_MODAL
		 | GTK_DIALOG_DESTROY_WITH_PARENT
		 | GTK_DIALOG_NO_SEPARATOR,
		 NULL);

#if 0
    switch(type) {
		case CERTMANUI_EXPIRED_DIALOG_EXPIRED:
			buf = g_strdup_printf(_("cert_nc_expired"), cert_name);
			break;
		case CERTMANUI_EXPIRED_DIALOG_NOCA:
			buf = g_strdup_printf(_("cert_nc_nocatovalidate"));
			break;
		case CERTMANUI_EXPIRED_DIALOG_NOCA_EXPIRED:
			buf = g_strdup_printf
				(_("cert_nc_nocatovalidateand_expired"), cert_name);
			break;
	}
    expired_label = gtk_label_new(buf);
    g_free(buf);
    buf = NULL;
#else
	expired_label = gtk_label_new(cert_name);
#endif
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
	maemosec_key_id cert_key;
	int rc, domain_flags;
	domain_handle dh = 0;
	X509 *cert = NULL;
	gboolean do_delete = FALSE;
	char* b64_cert = NULL;

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

	if (NULL == b64_cert) {

		MAEMOSEC_DEBUG(1, "%s: fetch %s:%s:%s:%s", __func__, 
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

	} else {
		unsigned len;
		unsigned char *cert_der = NULL;

		len = base64_decode(b64_cert, &cert_der);
		if (0 < len && NULL != cert_der) {
			const unsigned char* tmp = cert_der;
			MAEMOSEC_DEBUG(1, "%s: decoded %d bytes", __func__, len);
			cert = d2i_X509(NULL, &tmp, len);
		} else {
			MAEMOSEC_ERROR("%s: decoding failed", __func__);
		}
		if (cert_der)
			free(cert_der);
	}

	window = gtk_widget_get_ancestor(GTK_WIDGET(tree),
									 GTK_TYPE_WINDOW);

	do_delete = certmanui_certificate_details_dialog(window, domain_flags, cert);

	if (do_delete && NULL == b64_cert) {
		do_delete = certmanui_confirm(window, cert, "cert_nc_confirm_dialog");
	} else
		do_delete = FALSE;

	if (do_delete) {
		rc = maemosec_certman_open_domain(domain, domain_flags, &dh);
		if (0 == rc) {
			rc = maemosec_certman_rm_cert(dh, cert_key);
			if (0 == rc) {
				certmanui_info(window, NULL, "cert_ib_uninstalled");
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
	if (b64_cert)
		g_free(b64_cert);
	if (name_str)
		g_free(name_str);
	if (domain)
		g_free(domain);
	if (cert_id)
		g_free(cert_id);
	return;
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

gchar*
ask_password(gpointer window, 
			 int test_password(void* data, gchar* pwd), 
			 void* data, 
			 const char* info)
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


static gboolean
certmanui_install_certificates_dialog(gpointer window, 
									  STACK_OF(X509) *certs,
									  EVP_PKEY* pkey)
{
	GtkWidget* install_dialog = NULL;
	GtkListStore* contents_store = NULL;
	GtkWidget* contents_list = NULL;
	GtkWidget* scroller = NULL;
	GtkWidget *panarea = NULL;
	GtkWidget *bn_install = NULL;
    GtkTreeIter iter;
	GdkGeometry hints;
	char namebuf[255];
	int i, rc;
	gint ret;
	gboolean result = FALSE;
	const gchar *cert_type;

	MAEMOSEC_DEBUG(1, "Enter %s", __func__);

	install_dialog = gtk_dialog_new_with_buttons
		(_("cert_ti_install_certificates"),
		 GTK_WINDOW(window),
		 GTK_DIALOG_MODAL
		 | GTK_DIALOG_DESTROY_WITH_PARENT
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

	bn_install = gtk_dialog_add_button(GTK_DIALOG(install_dialog),
									  _("cert_bd_cd_install"), 
									  GTK_RESPONSE_APPLY);

	_create_certificate_list(&scroller, &contents_list, &contents_store);

	panarea = hildon_pannable_area_new();
	hildon_pannable_area_add_with_viewport(HILDON_PANNABLE_AREA(panarea),
										  GTK_WIDGET(contents_list));

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

		cder = NULL;
		len = i2d_X509(cert, &cder);
		
		if (0 > len || NULL == cder) {
			MAEMOSEC_ERROR("Failed to convert '%s' to DER", namebuf);
			continue;
		}

		b64cert = base64_encode(cder, len);
		MAEMOSEC_ERROR("%s: encoded %d bytes", __func__, len);

		gtk_list_store_append(contents_store, &iter);
		gtk_list_store_set(contents_store, &iter, 
						   MAIN_CONTENT_COL, b64cert, 
						   MAIN_DOM_TYPE_COL, INSTALL_CERT + 1,
						   -1);

		if (   0 == maemosec_certman_get_key_id(cert, key_id)
			&& 0 == maemosec_certman_key_id_to_str(key_id, key_id_str, sizeof(key_id_str)))
				gtk_list_store_set(contents_store, &iter, MAIN_ID_COL, key_id_str, -1);

		if (X509_check_ca(cert)) {
			cert_type = "cert_li_certificate_signing";
		} else if (NULL != pkey) {
			cert_type = "cert_li_certificate_user_key";
		} else {
			cert_type = "cert_li_certificate_user";
		}
		gtk_list_store_set(contents_store, &iter, 
						   MAIN_NAME_COL, _(cert_type),
						   MAIN_PURPOSE_COL, namebuf,
						   -1);
		free(b64cert);
		OPENSSL_free(cder);
	}

	MAEMOSEC_DEBUG(1, "Add pan area");
    gtk_container_add(GTK_CONTAINER(GTK_DIALOG(install_dialog)->vbox), panarea);

	MAEMOSEC_DEBUG(1, "Show all");
    gtk_widget_show_all(install_dialog);

	do {
        MAEMOSEC_DEBUG(1, "Before gtk_dialog_run");
        ret = gtk_dialog_run(GTK_DIALOG(install_dialog));
        MAEMOSEC_DEBUG(1, "After gtk_dialog_run ret=%d", ret);

        if (GTK_RESPONSE_APPLY == ret) {
			MAEMOSEC_DEBUG(1, "%s: Install!", __func__);
			result = TRUE;
			break;
        }
	} while (GTK_RESPONSE_DELETE_EVENT != ret);

    gtk_widget_hide_all(install_dialog);

    gtk_widget_destroy(scroller);
    scroller = NULL; 

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
	gint response;
	HildonTouchSelector *selector;
	GdkGeometry hints;
	GtkWidget* panarea;
	GtkWidget* bn_button;
	GList *selected;
	const struct pkcs12_target *tgt;

	MAEMOSEC_DEBUG(1, "Enter %s", __func__);
	
	*dialog = gtk_dialog_new_with_buttons(_("cert_ti_application_trust"),
										 GTK_WINDOW(window),
										 GTK_DIALOG_MODAL
										 | GTK_DIALOG_DESTROY_WITH_PARENT
										 | GTK_DIALOG_NO_SEPARATOR,
										 NULL);
    hints.min_width  = MIN_WIDTH;
    hints.min_height = MIN_HEIGHT;
    hints.max_width  = MAX_WIDTH;
    hints.max_height = MAX_HEIGHT;

	gtk_window_set_geometry_hints(GTK_WINDOW(*dialog), *dialog, &hints,
                                  GDK_HINT_MIN_SIZE | GDK_HINT_MAX_SIZE);

	bn_button = gtk_dialog_add_button(GTK_DIALOG(*dialog),
									  _("cert_bd_trust_settings_ok"),
									  GTK_RESPONSE_APPLY);

	selector = (HildonTouchSelector*)hildon_touch_selector_new_text();
	hildon_touch_selector_set_column_selection_mode
		(selector, HILDON_TOUCH_SELECTOR_SELECTION_MODE_MULTIPLE);

	for (tgt = pkcs12_targets; tgt->symbolic_name; tgt++) 
		hildon_touch_selector_append_text(selector, _(tgt->symbolic_name));

	panarea = hildon_pannable_area_new();
	hildon_pannable_area_add_with_viewport(HILDON_PANNABLE_AREA(panarea),
										   (GtkWidget*)selector);

    gtk_container_add(GTK_CONTAINER(GTK_DIALOG(*dialog)->vbox), panarea);

	MAEMOSEC_DEBUG(1, "Show dialog");
	gtk_widget_show_all(*dialog);

	MAEMOSEC_DEBUG(1, "Run dialog");
    response = gtk_dialog_run(GTK_DIALOG(*dialog));
	MAEMOSEC_DEBUG(1, "Response = %d", response);

	*domains = NULL;
	selected = hildon_touch_selector_get_selected_rows(selector, 0);
	while (selected) {
		GtkTreePath *sel = (GtkTreePath*)(selected->data);
		gchar* domain_name = pkcs12_targets[*gtk_tree_path_get_indices(sel)].domain_name;
		MAEMOSEC_DEBUG(1, "%s: selected '%s'", __func__, domain_name);
		*domains = g_list_append(*domains, g_strdup(domain_name));
		selected = selected->next;
	}
	g_list_free(selected);

	MAEMOSEC_DEBUG(1, "Exit %s", __func__);

	return(GTK_RESPONSE_APPLY == response && 0 < g_list_length(*domains));
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

	if (!extract_envelope(window, fileuri, &certs, &pkey, &password))
		return(FALSE);

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
		 * A packet of many certificates
		 */
		do_install = certmanui_install_certificates_dialog
			(window, certs, pkey);
		MAEMOSEC_DEBUG(1, "certmanui_install_certificates_dialog=%d", 
					   do_install);
		confirmation_text = "cert_ib_installed_certificates";
	}

	if (!do_install)
		goto cleanup;

	MAEMOSEC_DEBUG(1, "Ask purpose");

	do_install = ask_domains(window, &dialog, &domains);
		
	if (!do_install) 
		goto cleanup;

	MAEMOSEC_DEBUG(1, "About to install");
	while (domains) {
		char domain_name[256];
		char cert_name[256];
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
				/*
				 * TODO: Ask for a new password.
				 */
				if (pkey) {
					maemosec_key_id key_id;
					rc = maemosec_certman_get_key_id(cert, key_id);
					if (0 == rc) {
						rc = maemosec_certman_store_key(key_id, pkey, password?password:"");
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
