/* -*- mode:c++; tab-width:4; c-basic-offset:4; -*- */
/**
   @file cm_service.c

   Implements certman_service component for Certman CPA.

   Copyright (c) 2005-2006 Nokia. All rights reserved.

   Contact: Jakub Pavelek <jakub.pavelek@nokia.com>
*/

#define _XOPEN_SOURCE

#include <glib.h>
#include <gtk/gtk.h>
#include <gdk/gdkx.h>

#include <X11/Xlib.h>
#include <X11/X.h>
#include <X11/Xatom.h>

#include <stdio.h>
#include <libosso.h>

#include <assert.h>
#include <libintl.h>
#include <locale.h>
#include <unistd.h>
#include <string.h>

#include "dbus.h"
#include "ui/osso-applet-certman.h"
#include "../i18n.h"

static Window _get_window_property(Window xwindow, Atom atom);
static Atom _get_xatom_current_app_window(void);

extern osso_context_t *osso_global;
static osso_context_t *osso_aux = NULL;
static X509_STORE* root_store = NULL;

GMainLoop *mainloop = NULL;
GtkWidget *top_aux = NULL;
/* Display *dpy = NULL;  */

int main(int argc, char **argv) {

    gint result=0;
    Atom atom_c;
    Window active_window;

    setlocale(LC_ALL, "");
    bindtextdomain(LANGDOMAIN, LOCALEDIR);
    bind_textdomain_codeset(LANGDOMAIN, "UTF-8");
    textdomain(LANGDOMAIN);

	result = maemosec_certman_open(&root_store);
	MAEMOSEC_DEBUG(1, "%s: maemosec_certman_open returned %d", __func__, result);

    gtk_init(&argc, &argv);
    mainloop = g_main_loop_new(NULL, FALSE);

    top_aux = gtk_window_new(GTK_WINDOW_TOPLEVEL);

    Window root_window = gdk_x11_get_default_root_xwindow();
    g_assert(root_window);

    atom_c = _get_xatom_current_app_window();
    MAEMOSEC_DEBUG(1, "Got current app window");

    if (atom_c) active_window = _get_window_property(root_window, atom_c);
    else {
        MAEMOSEC_ERROR("Failed to get active_window");
        return OSSO_ERROR;
    }

    g_assert(active_window);

    GdkWindow *gdk_active_window = gdk_window_foreign_new(active_window);
    top_aux->window = gdk_active_window;

    g_assert(gdk_active_window);
    g_assert(top_aux);

    if (!osso_init(&osso_aux) || NULL == osso_aux) {
		MAEMOSEC_ERROR("Failed to get osso context");
        return OSSO_ERROR;
    }

    osso_global = osso_aux;

    MAEMOSEC_DEBUG(1, "** starting cm_service, got osso context");

    g_main_loop_run(mainloop);

    fprintf(stderr, "cm_service: quitted gtk main loop\n");

	result = maemosec_certman_close(root_store);
	MAEMOSEC_DEBUG(1, "%s: maemosec_certman_close returned %d", __func__, result);
	
    return 0;
}


/* Borrowed from libwnck */
static Window 
_get_window_property(Window xwindow, Atom atom) 
{

    Atom type;
    gint format;
    gulong nitems;
    gulong bytes_after;
    Window *w=NULL;
    gint err, result;
    Window retval;

    gdk_error_trap_push();

    type = None;
    result = XGetWindowProperty(gdk_display,
                                xwindow,
                                atom,
                                0, 
								G_MAXLONG,
                                False, 
								XA_WINDOW, 
								&type, 
								&format, 
								&nitems,
                                &bytes_after, 
								(guchar **)&w);
    err = gdk_error_trap_pop();

    if (err != Success ||
        result != Success)
        return None;

    if (type != XA_WINDOW)
    {
        XFree (w);
        return None;
    }

    retval = *w;
    XFree (w);

    return retval;
}


static Atom 
_get_xatom_current_app_window (void) 
{

    /*  GdkDisplay* gdk_display = NULL;  */
    Atom atom_q;

    gdk_display = GDK_DISPLAY();

    gdk_error_trap_push();

    for (atom_q = 1; ; atom_q++) {
        gchar *s = XGetAtomName(gdk_display, (Atom)atom_q);
        /*  fprintf(stderr, "\nAtom (%ld): %s\n", (long)atom_q, s);  */
        if (s!=NULL) {
            /* (strcmp(s, "_MB_CURRENT_APP_WINDOW") == 0) */

            if (g_ascii_strcasecmp((gchar *)s, "_MB_CURRENT_APP_WINDOW") == 0){
                /*  fprintf(stderr, "Got the current window !!\n");
                    fprintf(stderr, "wanted atom: %s\n", s); */
                XFree(s);
                gdk_error_trap_pop();
                return atom_q;
            }
            XFree(s);
        }
        else {
            gdk_error_trap_pop();
            return 0;
        }

    }
}
