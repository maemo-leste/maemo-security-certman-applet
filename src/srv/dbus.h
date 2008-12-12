/**
   @file dbus.h
   DBUS interactions header.
   <p>

   Copyright (c) 2005-2006 Nokia. All rights reserved.

   Contact: Jakub Pavelek <jakub.pavelek@nokia,com>
*/

#ifndef __DBUS_H__
#define __DBUS_H__

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <libosso.h>
#include <hildon/hildon.h>
#include <glib.h>
#include <gtk/gtk.h>
#include <osso-log.h>

#define OSSO_CM_SERVICE "com.nokia.certman"
#define OSSO_CM_INTERFACE "com.nokia.certman"
#define OSSO_CM_OBJECT_PATH "/com/nokia/certman"

#define DBUS_METHOD_MIME_OPEN       "mime_open"
#define DBUS_METHOD_TOP_APPLICATION "top_application"

/* Define d-bus messages, to which application have to react */
/* For instance game application needs methods to start, continue, restart,
   close and pause the game */

#define OSSO_CM_EXECUTE_METHOD "certman_exec"

/* Testing d-bus messaging with displaying infoprint */
#define OSSO_CM_DISPLAY_INFOPRINT "certman_display_infoprint"

void osso_top_callback(const gchar *arguments, gpointer *window);

gboolean set_dbus_handler(osso_rpc_cb_f *func);

/**
    Receive D-BUS messages and handle them

    @param interface The interface of the called method.
    @param method The method that was called.
    @param arguments A GArray of osso_rpc_t_structures.
    @param data An application specific pointer.
    @param retval The return value of the method.
    @returns gint value
*/
gint dbus_req_handler(const gchar *interface,
                      const gchar *method,
                      GArray *arguments,
                      gpointer app_data,
                      osso_rpc_t *retval);

osso_return_t osso_rpc_cb(const gchar *interface,
                          const gchar *method,
                          GArray *args,
                          gpointer data,
                          osso_rpc_t *retval);


/* Handles incoming D-BUS message

@param method The method that was called.
@param arguments A GArray of osso_rpc_t structures.
@param data An application specific pointer.
@param retval The return value of the method.
@returns gint value
*/
gint dbus_message_handler(const gchar *method,
                          GArray *arguments,
                          gpointer app_data,
                          osso_rpc_t *retval);


/**
   Set hardware event handler

   @param state Signals that are of interest
   @param cb Callback function.
   @param data Application specific data.
*/
gboolean set_hw_event_handler(osso_hw_state_t *state,
                              osso_hw_cb_f *cb,
                              gpointer data);


/**
    Handles hardware events.

    @todo Just a skeleton
    @param state State occured.
    @param data Application specific data.
*/
void hw_event_handler(osso_hw_state_t *state, gpointer data);

/**
   Osso topping callback

   @param arguments Extra parameters
   @param app_data Application specific data
*/
/**
   void osso_top_callback(const gchar *arguments, AppData *app_data);
*/

/**
   Initialize osso

   @param app Application specific data
   @returns TRUE on success, FALSE otherwise
*/

gboolean osso_init(osso_context_t **osso);

/**
   Deinitialize osso

   @returns TRUE on success, FALSE otherwise
*/

gboolean osso_deinit(osso_context_t *osso);

#endif /* __DBUS_H__ */
