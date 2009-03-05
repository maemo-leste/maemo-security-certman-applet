/* -*- mode:c++; tab-width:4; c-basic-offset:4; -*- */
/**
   @file applet_start.c

   Implements AppletStart and AppletReset components for Certman
   CPA. This includes all the interfaces provided for Control Panel.
   <p>
   Copyright (c) 2005-2006 Nokia. All rights reserved.

   Contact: Jakub Pavelek <jakub.pavelek@nokia.com>
*/
#define _XOPEN_SOURCE

#include <glib.h>
#include <gtk/gtk.h>

#include <libosso.h>
#include <osso-log.h>

#include <assert.h>
#include <string.h>
#include <hildon/hildon.h>
#include <maemosec_common.h>
#include <maemosec_certman.h>

#include "applet_start.h"
#include "ui/interface.h"
#include "ui/osso-applet-certman.h"

#include "i18n.h"

const maemosec_key_id MAEMOSEC_EMPTY_KEY_ID = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

/**
   Function to quit.

   @param data        Pointer to main dialog.
*/


static void _quit(gpointer data);

/* Implementation */

GtkWidget* main_dialog = NULL;

/* See settings_internalize.c */
extern osso_context_t *osso_global;
X509_STORE* root_store = NULL;

/**
 * Definition of execute interface for Certman applet, used by any calling
 * application (primary user: Control Panel application).
 *
 * @param osso  osso context of the calling application.
 * @param data  Pointer to gtk window of the calling application.
 * @param user_activated   Flag indicating calling mode, either normal user
 *                         activation or system activation.
 */

osso_return_t 
execute(osso_context_t * osso, 
		gpointer data,
		gboolean user_activated)
{
    gint ret = -1, tret = 0;

    MAEMOSEC_DEBUG(1, "Enter %s", __func__);
	ULOG_CRIT_L("ULOG_CRIT_L works?");

    ret = bindtextdomain(LANGDOMAIN, LOCALEDIR);
    MAEMOSEC_DEBUG(1, "bindtextdomain('%s','%s') returns %d",
				   LANGDOMAIN, LOCALEDIR, ret);

    /* Get configuration from SettingsInternalize */

    if (osso == NULL) {
        ULOG_CRIT("Applet execute() called with NULL osso context.. aborting");
        return OSSO_ERROR;
    }
    
    MAEMOSEC_DEBUG(1, "About to set osso_global");
	osso_global = osso;

	ret = maemosec_certman_open(&root_store);
	MAEMOSEC_DEBUG(1, "maemosec_certman_open returned %d", ret);

    /*
      settings_init();

      if (get_configuration(NULL) == OSSO_ERROR)
      {
      gtk_infoprint(GTK_WINDOW(data), "Unable to open CST storage");
      ULOG_CRIT_L("Unable to load configuration..");
      _quit(main_dialog);
      return OSSO_ERROR;
      }
    */
    /* Create the main dialog and refresh it */
    main_dialog = ui_create_main_dialog(data);

    if (main_dialog == NULL)
    {
        ULOG_CRIT_L("Unable to create applet dialog, exiting..");
        return OSSO_ERROR;
    }

    ui_refresh();

    /* Run dialog */
    while (ret != CM_RESPONSE_CLOSE &&
           ret != GTK_RESPONSE_DELETE_EVENT &&
           ret != GTK_RESPONSE_CANCEL)
    {
        ret = gtk_dialog_run(GTK_DIALOG(main_dialog));

    }

    /* Check response code from the dialog */
    if (ret == CM_RESPONSE_CLOSE)
    {
        if (tret == OSSO_ERROR) {
            ULOG_CRIT_L("Unable to save configuration..");
        }
    }

    /* Quit */
    _quit(main_dialog);


    /* If response from dialog was ok, return tret */
    if (ret == GTK_RESPONSE_OK)
    {
        /* osso_cp_plugin_ok(osso, NAME); */
        return tret;
    }

    return OSSO_OK;
}

static void _quit(gpointer dialog)
{
	gint ret;
    /* Delete ui */
	MAEMOSEC_DEBUG(1, "Enter %s", __func__);
    if (dialog != NULL)
    {
        ui_destroy();
    }

    /* Destroy SettingsDatabase */
	ret = maemosec_certman_close(root_store);
	MAEMOSEC_DEBUG(1, "maemosec_certman_close returned %d", ret);
}
