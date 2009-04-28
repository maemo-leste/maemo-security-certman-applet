/* -*- mode:c; tab-width:4; c-basic-offset:4; -*- */

#include "cm_envelopes.h"
#include <libgnomevfs/gnome-vfs.h>
#include <libgnomevfs/gnome-vfs-result.h>
#include <openssl/x509v3.h>
#include <maemosec_common.h>
#include <maemosec_certman.h>
#include "cm_dialogs.h"

typedef enum {
    MMC_NONEXISTING = 0,
    MMC_INTERNAL,
    MMC_EXTERNAL
} MmcSlot;

#define DEFAULT_SUFFIX          ".cer"
#define PEM_SUFFIX              ".pem"
#define DER_SUFFIX              ".der"
#define PFX_SUFFIX              ".pfx"
#define P12_SUFFIX              ".p12"

#define DEFAULT_SUFFIX01        ".crt"

#define CERT_MIMETYPE1          "application/x-x509-user-cert"
#define CERT_MIMETYPE2          "application/x-x509-ca-cert"
#define CERT_MIMETYPE3          "application/x-x509-email-cert"

#define USER_AREA_ENV           "HOME"
#define MMC_AREA_ENV            "MMC_MOUNTPOINT"
#define MMC_AREA_INTERNAL_ENV   "INTERNAL_MMC_MOUNTPOINT"
#define MMC_AREA_FALLBACK       "/media/mmc1"
#define MMC_AREA_INTERNAL_FALLBACK "/media/mmc2"



const char*
determine_filetype(FILE* fp, void** idata)
{
	X509* cert;
	PKCS12* cont;

	rewind(fp);
	cert = PEM_read_X509(fp, NULL, 0, NULL);
	if (cert) {
		*idata = (void*)cert;
		return("X509-PEM");
	} else
		MAEMOSEC_DEBUG(1, "Not a PEM file");

	rewind(fp);
	cert = d2i_X509_fp(fp, NULL);
	if (cert) {
		*idata = (void*)cert;
		return("X509-DER");
	} else
		MAEMOSEC_DEBUG(1, "Not a DER file");

	rewind(fp);
	cont = d2i_PKCS12_fp(fp, NULL);
	if (cont) {
		*idata = (void*)cont;
		return("PKCS12");
	} else
		MAEMOSEC_DEBUG(1, "Not a PKCS12 file");

	// TODO: Bare key file "evp.h"

	return("Unknown");
}

/*
 * Check out how much info can be shown about a PKCS12
 * container without giving the actual password. Code
 * borrowed from openssl crypto/pkcs12/p12_kiss.c
 */
static void 
show_pkcs7_info(STACK_OF(PKCS12_SAFEBAG) *bags)
{
	PKCS12_SAFEBAG* bag;
	X509_ATTRIBUTE* attrib;
	int i, j;

	if (!bags) {
		MAEMOSEC_ERROR("cannot decode PKCS7 container");
		return;
	}
	MAEMOSEC_DEBUG(2, "    %d safebags", sk_PKCS12_SAFEBAG_num(bags));
	for (i = 0; i < sk_PKCS12_SAFEBAG_num(bags); i++) {
		bag = sk_PKCS12_SAFEBAG_value(bags, i);
		if (bag) {
			char buf[64];
			const char* bagtype = "";
			switch(M_PKCS12_bag_type(bag)) {
				case NID_pkcs8ShroudedKeyBag:
					bagtype = "PKCS#8 Shrouded Keybag";
					break;
				case NID_certBag:
					bagtype = "Certificate";
					break;
			    default:
					sprintf(buf, "bagtype NID %d", M_PKCS12_bag_type(bag));
					bagtype = (const char*)buf;
			}
			MAEMOSEC_DEBUG(2, "      bag #%d '%s' type %s", i, 
						   PKCS12_get_friendlyname(bag),
						   bagtype);
			if (bag->attrib) {
				for (j = 0; j < sk_X509_ATTRIBUTE_num(bag->attrib); j++) {
					attrib = sk_X509_ATTRIBUTE_value(bag->attrib, j);
					if (attrib) 
						MAEMOSEC_DEBUG(2, "        attrib %d: NID %d", j, 
									   OBJ_obj2nid(attrib->object));
				}
			}
		}
	}
	sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
}


static int
test_pkcs12_password(void* on_data, gchar* password)
{
	PKCS12* data = (PKCS12*) on_data;
	
	if (data) {
		if (password) {
			if (PKCS12_verify_mac(data, password, strlen(password))) {
				MAEMOSEC_DEBUG(1, "'%s' is the correct password", password);
				return(1);
			} else {
				MAEMOSEC_DEBUG(1, "'%s' is not the correct password", password);
			}
		} else if (PKCS12_verify_mac(data, NULL, 0)) {
			MAEMOSEC_DEBUG(1, "NULL is the correct password");
			return(1);
		} else {
			MAEMOSEC_DEBUG(1, "NULL is not the correct password");
			return(0);
		}
	} else {
		MAEMOSEC_DEBUG(1, "No data!");
	}
	return(0);
}


static void
show_pkcs12_info(PKCS12* data)
{
	STACK_OF(PKCS7) *asafes;
	PKCS7 *p7;
	int i, bagnid;

	asafes = PKCS12_unpack_authsafes(data);
	if (!asafes) {
		MAEMOSEC_ERROR("PKCS12_unpack_authsafes returned NULL");
		return;
	}

	MAEMOSEC_DEBUG(2, "%d asafes", sk_PKCS7_num(asafes));
	for (i = 0; i < sk_PKCS7_num(asafes); i++) {
		p7 = sk_PKCS7_value(asafes, i);
		bagnid = OBJ_obj2nid(p7->type);
		switch (bagnid)	{
			case NID_pkcs7_data:
				MAEMOSEC_DEBUG(2, "  %d: PKCS#7 data", i);
				show_pkcs7_info(PKCS12_unpack_p7data(p7));
				break;
			case NID_pkcs7_encrypted:
				MAEMOSEC_DEBUG(2, "  %d: PKCS#7 encrypted data", i);
				show_pkcs7_info(PKCS12_unpack_p7encdata(p7, "wifi", 4));
				break;
			default:
				MAEMOSEC_DEBUG(2, "  %d: NID %d", i, bagnid);
				break;
		}
	}

	sk_PKCS7_pop_free(asafes, PKCS7_free);
}

#define BUFFER_SIZE 1024

static GnomeVFSResult 
_uri_to_temp(const gchar* uri, FILE** fp)
{
    FILE* tmpfp = NULL;
    GnomeVFSHandle* handle = NULL;
    GnomeVFSResult result = GNOME_VFS_OK;
    GnomeVFSFileSize size = 0;
    guint8 buffer[BUFFER_SIZE];
    size_t wsize = 0;

    MAEMOSEC_DEBUG(1, "Enter %s", __func__);

    /* Set return fp as NULL */
    *fp = NULL;

    /* Open given URI for reading */
    result = gnome_vfs_open(&handle, uri, GNOME_VFS_OPEN_READ);
    if (result != GNOME_VFS_OK) {
		MAEMOSEC_ERROR("%s: gnome_vfs_open failed, rc = %d", __func__, result); 
		return(result);
	}

    /* Open tmpfile */
    tmpfp = tmpfile();
    if (tmpfp == NULL) {
		MAEMOSEC_ERROR("%s: cannot create tmpfile", __func__); 
		return(GNOME_VFS_ERROR_NO_SPACE);
	}

    /* Read from URI and write it to tmpfile */
    do
    {
        result = gnome_vfs_read(handle, (gpointer)buffer,
                                BUFFER_SIZE, &size);
        if (size > 0)
        {
            wsize = fwrite((void*)buffer, 1, (size_t)size, tmpfp);

            if (wsize != (size_t)size)
            {
                MAEMOSEC_ERROR("Wrong number of bytes written");
            }
        }

    } while (size > 0 && result == GNOME_VFS_OK);

    /* Close GnomeVFS Handle */
    gnome_vfs_close(handle);

    /* Return error result */
    if (result != GNOME_VFS_ERROR_EOF &&
        result != GNOME_VFS_OK)
    {
        fclose(tmpfp);
		MAEMOSEC_ERROR("%s: gnome vfs error %d", __func__, result); 
        return(result);
    }

    /* Save tmpfile FILE* to return value and return GNOME_VFS_OK */
    rewind(tmpfp);
    *fp = tmpfp;
    return(GNOME_VFS_OK);
}


/*
 * Return the number of certficates found in the envelope
 */ 
 
gboolean
extract_envelope(gpointer window,
				 const char* fileuri,
				 STACK_OF(X509) **certs,
				 EVP_PKEY **pkey,
				 gchar** password
) {
	int rc;
    FILE *fp = NULL;
	const char* shortname;
	const char* filetype;
	void* idata;

	if (GNOME_VFS_OK != _uri_to_temp(fileuri, &fp)) {
		MAEMOSEC_ERROR("Cannot open '%s'", fileuri);
		return(FALSE);
	}
	shortname = strrchr(fileuri, '/');
	if (!shortname)
		shortname = fileuri;
	else
		shortname++;
	filetype = determine_filetype(fp, &idata);
	MAEMOSEC_DEBUG(1, "'%s' seems to be '%s'", shortname, filetype);

	/*
	 * TODO: Are there envelopes that can contain more than
	 * one private key? Is there a STACK_OF(EVP_PKEY)?
	 */

	*pkey = NULL;
	*password = NULL;

	if (0 == strcmp(filetype, "PKCS12")) {
		X509* cert = NULL;
		STACK_OF(X509) *cas = NULL;
			
		MAEMOSEC_DEBUG(1, "try to parse PKCS12");
		show_pkcs12_info((PKCS12*)idata);

		/*
		if (test_pkcs12_password(*idata, NULL))
			*password = NULL;
		else
		*/
		if (test_pkcs12_password(idata, ""))
			*password = g_strdup("");
		else
			*password = ask_password(window, test_pkcs12_password, idata, shortname);

		rc = PKCS12_parse((PKCS12*)idata, *password, pkey, &cert, &cas);
		MAEMOSEC_DEBUG(1, "parse PKCS12 returned %d", rc);

		if (0 != rc) {
			int i;
			char nickname[256];

			*certs = sk_X509_new_null();
			if (NULL != cert) {
				rc = maemosec_certman_get_nickname(cert, nickname, sizeof(nickname));
				MAEMOSEC_DEBUG(1, "Adding user cert '%s' (%d)", nickname, rc);
				sk_X509_push(*certs, X509_dup(cert));
				X509_free(cert);
			}
			for (i = 0; i < sk_X509_num(cas); i++) {
				cert = sk_X509_value(cas, i);
				rc = maemosec_certman_get_nickname(cert, nickname, sizeof(nickname));
				MAEMOSEC_DEBUG(1, "Adding CA cert '%s' (%d)", nickname, rc);
				sk_X509_push(*certs, X509_dup(cert));
			}
			sk_X509_free(cas);
			return(0 < sk_X509_num(*certs));
		} else
			return(FALSE);

	} else if (0 == strcmp(filetype, "X509-PEM")
		   ||  0 == strcmp(filetype, "X509-DER")) 
	{
		*certs = sk_X509_new_null();
		sk_X509_push(*certs, (X509*)idata);
		return(TRUE);

	} else {
		MAEMOSEC_ERROR("Unsupported filetype '%s'", filetype);
		return(FALSE);
	}
}
