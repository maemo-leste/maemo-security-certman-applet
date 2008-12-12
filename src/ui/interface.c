/* -*- mode:c++; tab-width:4; c-basic-offset:4; -*- */
/**
   @file interface.c

   UI implementation for the Certificate Manager CPA.

   Copyright (c) 2005 Nokia. All rights reserved.

   @author  Karoliina T. Salminen <karoliina.t.salminen@nokia.com>
*/

#include <libosso.h>
#include <osso-log.h>
#include <stdio.h>
#include <gtk/gtk.h>

#include <assert.h>
#include <string.h>
#include <time.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <maemosec_common.h>

#include <hildon/hildon.h>

#include "callbacks.h"
#include "interface.h"
#include "i18n.h"
#include "uidefs.h"
#include "uiutils.h"
#include "osso-applet-certman.h"

/* How many certificates are populated at a time */
#define NUM_POPULATE_CERTIFICATES 1
#define NULL_CERT 0

// TODO: Get rid of this
extern osso_context_t *osso_global;

/* Local interface */

/**
   Creates a certificate list.

   @param type
   @param scroller
   @param list
   @param list_store
*/
static void _create_certificate_list(AuthType type,
                                     GtkWidget** scroller,
                                     GtkWidget** list,
                                     GtkListStore** list_store);

/**
   Populate certificates of a given type.
*/
static int 
_populate_certificates(int pos,
					   const char* from_name,
					   GtkListStore* store);


/* Implementation */

/* Main dialog related stuff */
GtkWidget* dialog = NULL;
GtkWidget* notebook = NULL;

/* notebook pages */
GtkWidget* user_page = NULL;
GtkWidget* auth_page = NULL;

/* Lists */
GtkWidget* user_list = NULL;
GtkListStore* user_list_store = NULL;
GtkWidget* user_scroller = NULL;
GtkWidget* auth_list = NULL;
GtkListStore* auth_list_store = NULL;
GtkWidget* auth_scroller = NULL;

/* Labels */
GtkWidget* user_nocerts_label = NULL;
GtkWidget* auth_nocerts_label = NULL;

GtkWidget* remember_checkbox = NULL;

/* Other globals */
GdkGeometry hints;
RowParameter row_params[2];
ButtonParameter button_param;
RowActivatedParameter rowact_param;

/* These are found in details.c
   extern GtkWidget* cert_dialog;
   extern GtkWidget* cert_simple_dialog;
*/

/* These are found in importexport.c */
extern gboolean close_store_on_exit;


static gboolean 
delete_event(GtkWidget *widget, GdkEvent *event, gpointer null)
{
	gtk_dialog_response(GTK_DIALOG(widget), CM_RESPONSE_CLOSE);
	return TRUE;
}


GtkWidget* 
ui_create_main_dialog(gpointer window) 
{
    /* Initialize local stuff */
    GtkWidget* view_button = NULL;
    // GtkWidget* delete_button = NULL;

	int rc;

    if (window == NULL)
    {
        return NULL;
    }

    GtkSizeGroup *group = GTK_SIZE_GROUP(
        gtk_size_group_new( GTK_SIZE_GROUP_HORIZONTAL));

	MAEMOSEC_DEBUG(1, "Enter");

    /* Load image content */
    close_store_on_exit = FALSE;

    /* Create dialog and set its attributes */
    dialog = gtk_dialog_new_with_buttons(_("cert_ti_main_dialog"),
                                         GTK_WINDOW(window),
                                         GTK_DIALOG_MODAL
                                         | GTK_DIALOG_DESTROY_WITH_PARENT
                                         | GTK_DIALOG_NO_SEPARATOR,
                                         NULL);

    if (dialog == NULL)
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

    /* Create dialog buttons */
    view_button = gtk_button_new_with_label(_("cert_bd_c_view"));
    gtk_container_add(GTK_CONTAINER(GTK_DIALOG(dialog)->action_area),
                      view_button);

    gtk_dialog_add_button(GTK_DIALOG(dialog), _("cert_bd_details_close"),
                          CM_RESPONSE_CLOSE);

    /* Create dialog widgets */
    user_page = gtk_vbox_new(FALSE, 0);
    auth_page = gtk_vbox_new(FALSE, 0);

    user_nocerts_label = gtk_label_new(
        _("ckdg_va_select_object_no_certificates"));

    gtk_container_add(GTK_CONTAINER(user_page), user_nocerts_label);

    _create_certificate_list(AUTH_USER,
                             &user_scroller,
                             &user_list,
                             &user_list_store);

    gtk_container_add(GTK_CONTAINER(user_page), user_scroller);

    auth_nocerts_label = gtk_label_new(
        _("ckdg_va_select_object_no_certificates"));

    gtk_container_add(GTK_CONTAINER(auth_page), auth_nocerts_label);

    _create_certificate_list(AUTH_ROOT,
                             &auth_scroller,
                             &auth_list,
                             &auth_list_store);

    gtk_container_add(GTK_CONTAINER(auth_page), auth_scroller);

    notebook = gtk_notebook_new();

    /* Set widget contents */

    /* Add pages to notebook */
    gtk_notebook_append_page(GTK_NOTEBOOK(notebook),
                             user_page, NULL);
    gtk_notebook_set_tab_label_text(GTK_NOTEBOOK(notebook),
                                    user_page,
                                    _("cert_ti_main_notebook_user"));

    gtk_notebook_append_page(GTK_NOTEBOOK(notebook),
                             auth_page, NULL);
    gtk_notebook_set_tab_label_text(GTK_NOTEBOOK(notebook),
                                    auth_page,
                                    _("cert_ti_main_notebook_authorities"));

    /* Add notebook to dialog */
    gtk_container_add(GTK_CONTAINER(GTK_DIALOG(dialog)->vbox), notebook);

    /* Setup signal handlers */

    /* Setup for lists */
    row_params[0].view = GTK_TREE_VIEW(user_list);
    row_params[0].list = user_list_store;
    row_params[0].type = AUTH_USER;
    row_params[0].iter_valid = FALSE;
    row_params[0].view_button = view_button;
    g_signal_connect(G_OBJECT(gtk_tree_view_get_selection(GTK_TREE_VIEW(user_list))),
                     "changed",
                     G_CALLBACK(list_selection_changed),
                     &row_params[0]);

    row_params[1].view = GTK_TREE_VIEW(auth_list);
    row_params[1].list = auth_list_store;
    row_params[1].type = AUTH_ROOT;
    row_params[1].iter_valid = FALSE;
    row_params[1].view_button = view_button;
    g_signal_connect(
		G_OBJECT(gtk_tree_view_get_selection(GTK_TREE_VIEW(auth_list))),
		"changed",
		G_CALLBACK(list_selection_changed),
		&row_params[1]);

    /* Setup for buttons */
    button_param.rows = row_params;
    button_param.notebook = GTK_NOTEBOOK(notebook);
    button_param.dialog = dialog;

    /* Connecting signals */
    g_signal_connect(G_OBJECT(view_button), "clicked",
                     G_CALLBACK(view_button_clicked),
                     &button_param);

    hildon_helper_set_insensitive_message (
		view_button, 
		_("cert_bd_no_certificates_to_view"));

    g_signal_connect(G_OBJECT(notebook), "switch-page",
                     G_CALLBACK(notebook_switch_page),
                     &button_param);

    /* Setup for row-activated */
    rowact_param.id_col = MAIN_ID_COL;
    rowact_param.simple = FALSE;

    g_signal_connect(G_OBJECT(user_list), "row-activated",
                     G_CALLBACK(cert_list_row_activated),
                     &rowact_param);

    g_signal_connect(G_OBJECT(auth_list), "row-activated",
                     G_CALLBACK(cert_list_row_activated),
                     &rowact_param);

    /* 
	 * Closes dialog on close event. Signal is emited by ESC hard key.
     * GtkDialog does not close it because we do not have an button which
     * returns GTK_RESPONSE_CANCEL
	 */

    g_signal_connect(G_OBJECT(dialog), "delete-event",
                     G_CALLBACK(delete_event), NULL);

    /* Disable export and view by default */
    gtk_widget_set_sensitive(view_button, FALSE);

    /* Add context sensitive help icon */
    hildon_help_dialog_help_enable(GTK_DIALOG(dialog),
                                CM_HELP_KEY_MAIN,
                                osso_global);

    /* Update lists. Do this before calling show on the notebook so
       that the notebook_switch_page can select a possible first row*/

	MAEMOSEC_DEBUG(1, "Populate root certificates");
	rc = maemosec_certman_iterate_domains(MAEMOSEC_CERTMAN_DOMAIN_SHARED,
										  _populate_certificates,
										  auth_list_store);
	if (0 != rc) {
		MAEMOSEC_ERROR("%s ret %d", 
					   "maemosec_certman_iterate_domains",
					   rc);
	}

	MAEMOSEC_DEBUG(1, "Populate user certificates");
	rc = maemosec_certman_iterate_domains(MAEMOSEC_CERTMAN_DOMAIN_PRIVATE,
										  _populate_certificates,
										  user_list_store);
	if (0 != rc) {
		MAEMOSEC_ERROR("%s ret %d", 
					   "maemosec_certman_iterate_domains",
					   rc);
	}

    /* Display dialog */
    gtk_widget_show_all(dialog);

    /* Set focus on the notebook instead of the list of certificates,
       because the focus an an possible empty list is confuding */
    gtk_widget_grab_focus(notebook);


    g_object_unref(group);
    group = NULL;

    return dialog;
}

void ui_refresh(void)
{
    GtkTreeIter iter;

    /* UI refreshing.. */
    /* Do not refresh, if dialog doesn't exist */
    if (dialog == NULL) return;

    if (!gtk_tree_model_get_iter_first(GTK_TREE_MODEL(user_list_store),
                                       &iter))
    {
        gtk_widget_show(user_nocerts_label);
        gtk_widget_hide(user_list);
    } else {
        gtk_widget_show(user_list);
        gtk_widget_hide(user_nocerts_label);
    }

    if (!gtk_tree_model_get_iter_first(GTK_TREE_MODEL(auth_list_store),
                                       &iter))
    {
        gtk_widget_show(auth_nocerts_label);
        gtk_widget_hide(auth_list);
    } else {
        gtk_widget_show(auth_list);
        gtk_widget_hide(auth_nocerts_label);
    }
}


void ui_destroy(void)
{
    if (dialog == NULL) 
		return;

    /* Delete main dialog */
    gtk_widget_destroy(dialog); 
	dialog = NULL;

    /* release pixbuf cache */
    release_pixbufs();
}

typedef struct cert_display_info {
	const char* domain_name;
	GtkListStore* store;
	GtkTreeIter* iter;
} *cert_display_info;


static void
print_key_id(maemosec_key_id key_id, char* to_buf, unsigned max_len)
{
	unsigned i;

	if (max_len < 3*MAEMOSEC_KEY_ID_LEN)
		return;
	for (i = 0; i < MAEMOSEC_KEY_ID_LEN; i++) {
		sprintf(to_buf, "%s%02hX", i?":":"", key_id[i]);
		to_buf += strlen(to_buf);
	}
}

static int
fill_cert_data(int pos, X509* cert, void* info)
{
	gchar *name_str = NULL;
	cert_display_info cd_info = (cert_display_info) info;
	maemosec_key_id key_id;
	char key_str[64];

	MAEMOSEC_DEBUG(1, "Enter %d:%p:%p", pos, cert, info);

	gtk_list_store_append(cd_info->store, cd_info->iter);

	name_str = X509_NAME_to_str(X509_get_subject_name(cert), FALSE);

	MAEMOSEC_DEBUG(1, "Add '%s' to '%p'", name_str, cd_info->store);

	gtk_list_store_set(cd_info->store, cd_info->iter, MAIN_NAME_COL, name_str, -1);
	g_free(name_str);

	gtk_list_store_set(cd_info->store, 
					   cd_info->iter, 
					   MAIN_PURPOSE_COL, 
					   get_purpose_name(cd_info->domain_name), 
					   -1);

	/*
	 * Invisible columns
	 */
	maemosec_certman_get_key_id(cert, key_id);
	print_key_id(key_id, key_str, sizeof(key_str));
	gtk_list_store_set(cd_info->store, cd_info->iter, MAIN_ID_COL, key_str, -1);
	gtk_list_store_set(cd_info->store, cd_info->iter, MAIN_DOMAIN_COL, cd_info->domain_name, -1);

	return(0);
}


static int 
_populate_certificates(int pos, const char* domain_name, GtkListStore* store)
{
    GtkTreeIter iter;
    int rc, domain_flags;
	domain_handle my_domain;
	struct cert_display_info cd_info;

	MAEMOSEC_DEBUG(1, "Enter, open domain '%s' for %p", domain_name, store);

	if (store == auth_list_store)
		domain_flags = MAEMOSEC_CERTMAN_DOMAIN_SHARED;
	else
		domain_flags = MAEMOSEC_CERTMAN_DOMAIN_PRIVATE;

	rc = maemosec_certman_open_domain(domain_name, 
									  domain_flags,
									  &my_domain);

	MAEMOSEC_DEBUG(1, "%s(%s) ret %d", "maemosec_certman_open_domain",
				   domain_name, rc);
	if (0 != rc)
		return(rc);

	MAEMOSEC_DEBUG(1, "%s contains %d certificates", domain_name, 
				   maemosec_certman_nbrof_certs(my_domain));

	cd_info.domain_name = domain_name;
	cd_info.store = store;
	cd_info.iter = &iter;
	rc = maemosec_certman_iterate_certs(my_domain, fill_cert_data, &cd_info);
	if (0 != rc)
		return(rc);

	rc = maemosec_certman_close_domain(my_domain);
	return(0);
}

static void 
_create_certificate_list(AuthType type,
						 GtkWidget** scroller,
						 GtkWidget** list,
						 GtkListStore** list_store)
{
    GtkCellRenderer* renderer = NULL;
    GtkTreeViewColumn* column = NULL;

    *list_store = gtk_list_store_new(MAIN_NUM_COLUMNS, 
									 GDK_TYPE_PIXBUF,    /* MAIN_IMAGE_COL */
                                     G_TYPE_BOOLEAN,     /* MAIN_VALIDITY_COL  */
                                     G_TYPE_STRING,      /* MAIN_NAME_COL */
									 G_TYPE_STRING,      /* MAIN_ISSUED_COL (issuer, really */
                                     G_TYPE_STRING,      /* MAIN_PURPOSE_COL */ 
									 G_TYPE_STRING,      /* MAIN_ID_COL (hidden) */
									 G_TYPE_STRING);     /* MAIN_DOMAIN_COL (hidden) */

    /* Create list */
    *list = gtk_tree_view_new_with_model(GTK_TREE_MODEL(*list_store));
	MAEMOSEC_DEBUG(1, "Created list %p as %s", *list_store, 
				   AUTH_ROOT == type ? "root" : "user");
    g_object_unref(*list_store);

    /* Create columns to the list */

    /* Certificate name column */
    renderer = gtk_cell_renderer_text_new();
    column = gtk_tree_view_column_new_with_attributes (
        _("cert_li_no_certificates_issuedto"),
        renderer,
        "text", MAIN_NAME_COL,
        NULL);
    gtk_tree_view_column_set_sort_column_id(column, MAIN_NAME_COL);
    gtk_tree_view_column_set_widget(column, NULL);
    gtk_tree_view_append_column (GTK_TREE_VIEW(*list), column);
    g_object_set(G_OBJECT(column), "fixed-width", NAME_COL_WIDTH,
                 "sizing", GTK_TREE_VIEW_COLUMN_FIXED, NULL);

    /* Certificate purpose column */
	if (type != AUTH_ROOT) {
		column = gtk_tree_view_column_new_with_attributes 
			(_("cert_li_no_certificates_purpose"),
			 renderer,
			 "text", 
			 MAIN_PURPOSE_COL,
			 NULL);
		gtk_tree_view_column_set_sort_column_id(column, MAIN_PURPOSE_COL);
		gtk_tree_view_column_set_widget(column, NULL);
		gtk_tree_view_append_column (GTK_TREE_VIEW(*list), column);
		g_object_set(G_OBJECT(column), 
					 "fixed-width", 
					 PURPOSE_COL_WIDTH,
					 "sizing", 
					 GTK_TREE_VIEW_COLUMN_FIXED, 
					 NULL);

	}
	
	/* Order the list initially according to the last column */
	gtk_tree_view_column_clicked (column);

    /* Set GtkTreeView headers visible */
    gtk_tree_view_set_headers_visible(GTK_TREE_VIEW(*list), TRUE);

    /* Create scroller for the list and set policies */
    /* 13.9.2005 GtkTreeView does not need a separate viewport */
    *scroller = create_scroller_without_viewport(*list);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(*scroller),
                                   GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    return;
}
