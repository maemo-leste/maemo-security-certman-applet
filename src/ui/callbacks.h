/**
   @file callbacks.h

   This module contains various callback handlers for handling events
   in the Certificate Manager CPA.
   <p>
   Copyright (c) 2005 Nokia. All rights reserved.

   @author  Karoliina T. Salminen <karoliina.t.salminen@nokia.com>
*/

#ifndef __CALLBACKS_H__
#define __CALLBACKS_H__

#include <glib.h>
#include <gtk/gtk.h>
#include <gdk/gdkkeysyms.h>
#include <hildon/hildon.h>
#include "uidefs.h"

#ifdef __cplusplus
extern "C" {
#endif

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

/**
   List selection in one of the certificate lists has been changed.

   @param treeselection
   @param user_data
*/
    void list_selection_changed(GtkTreeSelection *treeselection,
                                gpointer user_data);

/**
   Import button has been clicked.

   @param button
   @param user_data     ButtonParameter
*/
    void import_button_clicked(GtkButton *button,
                               gpointer user_data);

/**
   Export button has been clicked.

   @param button
   @param user_data     ButtonParameter
*/
    void export_button_clicked(GtkButton *button,
                               gpointer user_data);

/**
   View button has been clicked.

   @param button
   @param user_data     ButtonParameter
*/
    void view_button_clicked(GtkButton *button,
                             gpointer user_data);

/**
   Remember passwords has been clicked.

   @param button        Checkbutton
   @param user_data     NULL
*/
    void remember_passwords_toggled(GtkToggleButton* button,
                                    gpointer user_data);

/**
   Active notebook page has been changed.

   @param notebook      Notebook
   @param page          New notebook page
   @param page_num      Number of the new page
   @param user_data     ButtonParameter
*/
    void notebook_switch_page(GtkNotebook* notebook,
                              GtkNotebookPage* page,
                              guint page_num,
                              gpointer user_data);

/**
   A row has been activated from the list/tree.

   @param tree          List/tree, from which the row was activated
   @param path          Path to activated row
   @param col           Column, which was activated (not used).
   @param user_data     RowActivatedParameter
*/
    void cert_list_row_activated(GtkTreeView* tree,
                                 GtkTreePath* path,
                                 GtkTreeViewColumn* col,
                                 gpointer user_data);

/**
   A handler to circumvent a bug in Hildon: row-activated doesn't
   work. Tries to emulate row-activated and calls
   cert_list_row_activated with right parameters

   @param widget        Widget receiving the event, should be GtkTreeView.
   @param event         Event describing the button press.
   @param user_data     RowActivatedParameter
*/
    gboolean cert_list_button_pressed(GtkWidget *widget,
                                      GdkEventButton *event,
                                      gpointer user_data);

/**
   A handler for handling the insensitive press for widgets. Shows
   simple infonote.

   @param widget        Widget, which emitted the signal
   @param data          The shown infonote text.
*/
    void default_insensitive_press(GtkWidget* widget,
                                   gpointer data);

#ifdef __cplusplus
}
#endif
#endif /* __CALLBACKS_H__ */
