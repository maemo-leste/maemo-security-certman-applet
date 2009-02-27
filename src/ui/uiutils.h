/* -*- mode:c++; tab-width:4; c-basic-offset:4; -*- */
/**
   @file uiutils.h

   Some useful UI-utils for Certificate Manager.
   <p>
   Copyright (c) 2005 Nokia. All rights reserved.

   @author  Karoliina T. Salminen <karoliina.t.salminen@nokia.com>
*/

#ifndef __UIUTILS_H__
#define __UIUTILS_H__

#include <gtk/gtk.h>
#include <openssl/x509.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Found in help material */
#define CM_HELP_KEY_EXPORTFORMAT                                        \
    "Utilities_ControlPanelAppletCertificateManager_exportfileformat"
#define CM_HELP_KEY_MAIN          "Utilities_ControlPanelAppletCertificateManager_certificatemanager"
#define CM_HELP_KEY_DETAILS       "Utilities_ControlPanelAppletCertificateManager_certificatedetails"
#define CM_HELP_KEY_SELECTKEY     "Utilities_ControlPanelAppletCertificateManager_selectkey"

/* Those are not present in help contents, yet specified in UI spec */
#define CM_HELP_KEY_TRUST       "Utilities_ControlPanelAppletCertificateManager_trustsettings"
#define CM_HELP_KEY_INSTALL     "Utilities_ControlPanelAppletCertificateManager_installcertificate"
#define CM_HELP_KEY_INSTALLCA   "Utilities_ControlPanelAppletCertificateManager_installauthoritycertificate"
#define CM_HELP_KEY_ENTERPASS   "Utilities_ControlPanelAppletCertificateManager_enterpassword"
#define CM_HELP_KEY_CHANGEPASS  "Utilities_ControlPanelAppletCertificateManager_changepassword"

/**
   Gets a pixbuf representing the given certificate.

   @param certificate      Certificate, whose pixbuf is needed.
   @return Certificate's pixbuf. Do not unref these, but call release_pixbufs after usage.
*/
    GdkPixbuf* get_cert_pixbuf(X509* certificate, gboolean* valid);

/**
   Empties pixbuf cache.
*/
    void release_pixbufs(void);

/**
   Creates scroller.

   @param child
   @return scroller widget.
*/
    GtkWidget* create_scroller(GtkWidget* child);

/**
   Creates scroller without separate viewport adaptor widget.
   Use this function to add scrollbars for widgets that have native
   scroll support: GtkTreeView, GtkTextView, and GtkLayout.

   @param child
   @return scroller widget.
*/
    GtkWidget* create_scroller_without_viewport(GtkWidget* child);

/**
   Function to create a password query dialog.

   @param window                Parent window for the dialog.
   @param cert                  Certificate, which issued to information is
   shown in the dialog, or NULL, if not shown.
   @param title                 Title of the dialog
   @param label                 Label for the password entry
   @param ok_label              Label for the OK button
   @param cancel_label          Label for the Cancel button
   @param passwd_entry          Password entry of the created dialog.
   @param install_timeout       Is timeout installed.
   @param min_chars             Minumum number of chars, that must
   be entered.

   @return Widget representing the password dialog.
*/
    GtkWidget* create_password_dialog(gpointer window,
                                      X509* cert,
                                      const gchar* title,
                                      const gchar* greeting,
                                      const gchar* label,
                                      const gchar* ok_label,
                                      const gchar* cancel_label,
                                      GtkWidget** passwd_entry,
                                      gboolean install_timeout,
                                      guint min_chars);

/**
   Shows error message to user

   @param msg           Message to show
   @param infonote      TRUE, if it should be an infonote, else banner
*/
    void show_error_msg(GtkWindow* window, const gchar* msg,
                        gboolean infonote);

/**
   Return string representing a given X509_NAME.

   @param name          Name to convert
   @param longform      TRUE, if wanted in form (CN, OU, O)
   FALSE, if only CN is wanted.
   @return Newly allocated string representation.
*/
    gchar* X509_NAME_to_str(X509_NAME* name, gboolean longform);

	/**
	 *  Gets a certificate name for a given certificate.
	 * 
	 * @param cert       Certificate
	 * @return Newly allocated string of the name of the certificate.
	 */
    gchar* get_certificate_name(X509* cert);
	

	gchar* get_purpose_name(const char* for_domain_name);

	void pick_name_components_by_NIDS(X509_NAME* of_name, 
									  const int* nids, 
									  unsigned nbrofnids, 
									  void cb_func(unsigned char*,void*),
									  void* ctx);
  
#ifdef __cplusplus
}
#endif
#endif /* __UIUTILS_H__ */
