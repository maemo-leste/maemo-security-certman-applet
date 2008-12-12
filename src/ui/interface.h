/**
   @file interface.h

   File implementing the Representation-module (user interface).
   <p>
   Copyright (c) 2005 Nokia. All rights reserved.

   @author  Karoliina T. Salminen <karoliina.t.salminen@nokia.com>
*/

#ifndef __INTERFACE_H__
#define __INTERFACE_H__

#include <gtk/gtk.h>
#include "callbacks.h"

#ifdef __cplusplus
extern "C" {
#endif

    typedef enum {
        UPDATE_ALL,
        UPDATE_PIC,
        UPDATE_TEXT
    } UpdatePolicy;


/**

*/
    GtkWidget* ui_create_main_dialog(gpointer window);

/**

*/
    void ui_refresh(void);

/**

*/
    void ui_destroy(void);

    void new_certs_arrived();

#ifdef __cplusplus
}
#endif
#endif /* __INTERFACE_H__ */
