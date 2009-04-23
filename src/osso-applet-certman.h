/* -*- mode:c++; tab-width:4; c-basic-offset:4; -*- */
/**
   @file osso-applet-certman.h

   Certificate manager API for external usage.
   <p>
   Copyright (c) 2005 Nokia. All rights reserved.

   @author  Karoliina T. Salminen <karoliina.t.salminen@nokia.com>
*/

#ifndef __OSSO_APPLET_CERTMAN_H__
#define __OSSO_APPLET_CERTMAN_H__

#include <gtk/gtk.h>
#include <libosso.h>
#include <maemosec_certman.h>

/**
   Bool-type GConf-key, which describes if apps should remember
   certificate passwords or not.
*/
#define GCONF_DIR "/apps/osso/certman"
#define GCONF_REMEMBER_PASSWORDS_KEY "/apps/osso/certman/remember_passwords"

/**
   String-type GConf-key describing the filename, which is used for
   certificate storage.
*/
#define GCONF_FILENAME_KEY "/apps/osso/certman/filename"

#define GCONF_NEW_CERTS_KEY   GCONF_DIR "/newly_imported"

#ifdef __cplusplus
extern "C" {
#endif

    typedef enum {
        CERTMANUI_EXPIRED_DIALOG_EXPIRED,
        CERTMANUI_EXPIRED_DIALOG_NOCA,
        CERTMANUI_EXPIRED_DIALOG_NOCA_EXPIRED
    } CertmanUIExpiredDialogType;


    typedef enum {
        CERTMANUI_ERROR_NO_LONGER_TRUSTED,
        CERTMANUI_ERROR_NOT_VALID_SERVER_CERT,
        CERTMANUI_ERROR_NOT_VALID_USER_CERT,
        CERTMANUI_ERROR_UNABLE_TO_SAVE,
    } CertmanUIErrorType;

	gboolean certmanui_init(osso_context_t *osso_ext);

	gboolean certmanui_deinit(void);

/**
   Represents a details dialog in the UI. Blocks until this dialog
   is dismissed.

   @param window        Parent window for the dialog
   @param simple        Show simple certificate details dialog. Does not
                        include delete or change password buttons.
   @param certificate   Certificate, whose details are shown.
*/
    gboolean
	certmanui_certificate_details_dialog(gpointer window,
										 int domain_flags,
										 X509* certificate);

/**
   Imports a certificate from a given file.Certificate is added to
   the default certificate store. If private key for the certificate
   is found from the same file, then importing it is also attempted
   (with certmanui_import_private_key_file). Blocks until process is finished.

   @param window        Parent window for all created dialogs.
   @param fileuri       The URI of the file, from which the certificate
   is imported. if NULL, then select object dialog
   is presented to the user.
   @param root          TRUE, if certificate is to be installed as root CA.
   @param cert_id       The placeholder for the id of the imported
   certificate, or NULL if not interested.
   @param pk12_list  List of pk12 certificates.

   @return TRUE, if importing was succesful.
*/
    gboolean 
	certmanui_import_file(gpointer window,
						  const gchar* fileuri,
						  maemosec_key_id* cert_id, 
						  GSList **pk12_list);

/**
   Show a details dialog for unknown certificate (not in the store).
   Also install button is presented for installing the given
   certificate. Blocks, until the dialog is dismissed.

   @param window        Parent window for the dialog.
   @param cert          Unknown certificate.

   @return TRUE, if user decided to install the certificate and the
   installation was succesful.
*/
    gboolean 
	certmanui_install_certificate_details_dialog(gpointer window,
												 X509* cert);

/**
   Represent UI for deleting the given certificate.

   @param window        Parent window for the dialog.
   @param cert_id       Id of the certificate, which is to be deleted.

   @return TRUE, if certificate was deleted succesfully.
*/
    gboolean 
	certmanui_delete_certificate(gpointer window, 
								 maemosec_key_id cert_id);

/**
   Callback function for the certmanui_get_privatekey, if it is
   non-blocking.

   @param cert_id       The certificate ID, for which the private key is
   fetched
   @param key           The private key, which was fetched, or NULL, if it
   couldn't be fetched  (e.g. wrong password or the
   process was cancelled). Key must be freed after usage.
   @param password      Password of the given key for caching it. Must be
   dupped, if used outside this callback. May be NULL.
   @param user_data     User data given to certmanui_get_privatekey.
*/
    typedef void 
	(*PrivateKeyResponseFunc) (maemosec_key_id cert_id,
							   EVP_PKEY* key,
							   gchar* password,
							   gpointer user_data);
	
/**
   Callback function for the certman_certificate_expired, if it is
   non-blocking.

   @param expired       The status of expiration. TRUE => expired.
   @param user_data      User data given to certmanui_certificate_expired.
*/
    typedef void 
	(*CertificateExpiredResponseFunc) (gboolean expired,
									   gpointer user_data);

/**
   Show UI for getting the given private key. The function can be
   blocking or non-blocking.

   @param certID         The certificate ID, for which the private key is
   required.
   @param password      Pointer to newly allocated string, where the private
   key password is saved for caching. NULL, if not
   interested. NULL will be set as a password, if
   callback is used.
   @param callback      A callback function, which is called, when the
   private key is fetched. If callback is NULL, then
   function blocks, until private key is fetched.
   @param user_data     user data to be given to the callback, if it is
   used.

   @return The private key or NULL, if it couldn't be fetched or function 
   was called as non-blocking
*/
    EVP_PKEY* certmanui_get_privatekey(gpointer window, maemosec_key_id cert_id,
                                       gchar** password,
                                       PrivateKeyResponseFunc callback,
                                       gpointer user_data);

/**
   Cancels the UI for getting the private key. Use for cancelling a
   non-blocking private key password query. Registered callback is
   called as it is called in CANCEL-case.
*/
    void certmanui_cancel_privatekey(void);

/**
   Convenience function (version of certmanui_certificate_with_type())
   for server certificates (not stored in the certificate storage).

   @param window        Parent window for dialogs.
   @param type          Dialog type for the certificate expired dialog.
   @param cert_name     Certificate name, for which the expiration is examined.
   @param callback      A callback function, which is called, when the
   expired status is resolved. If callback is NULL,
   then function blocks, until expired status is
   resolved.
   @param user_data user data to be given to the callback, if it is
   used.

   @return FALSE, if certificate was accepted for use. TRUE, if
   certificate was not accepted for use. Always returns
   TRUE, if called as non-blocking.

*/
    gboolean 
	certmanui_certificate_expired_with_name(gpointer window,
											CertmanUIExpiredDialogType type,
											const gchar* cert_name,
											CertificateExpiredResponseFunc callback,
											gpointer user_data);
/**     
    Convenience function (version of certmanui_certificate_with_type())
	for server certificates (not stored in the certificate storage).

	Show Certificate Manager related error in the UI.

	@param window           Parent window for the note/banner.
	@param type             Type of the error to be shown.
	@param cert_name        Name string for the certificate.
	@param cert_serial      Serial sting for the certificate.
	@param param            Other error message related info.
	@param callback         A callback function, which is called, when user
	has dismisssed the error note. Called instantly,
	if error is shown in a banner. Callback is called,
	with the return status of the function. If NULL,
	function is called as blocking (if it shows infonote).
	@param user_data       User data to be given to the callback, if it
	is used.
	
	@return TRUE, if error could be shown succesfully, FALSE otherwise.
	Returns always TRUE, if called as non-blocking.
*/
    gboolean 
	certmanui_show_error_with_name_and_serial(gpointer window,
											  CertmanUIErrorType type,
											  const gchar* cert_name,
											  const gchar* cert_serial,
											  gpointer param,
											  CertificateExpiredResponseFunc callback,
											  gpointer user_data);


#ifdef __cplusplus
}
#endif
#endif
