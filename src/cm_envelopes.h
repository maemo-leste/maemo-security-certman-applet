/* -*- mode:c; tab-width:4; c-basic-offset:4; -*- */

#ifndef CM_ENVELOPES_H
#define CM_ENVELOPES_H

#include <stdio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <gtk/gtk.h>

typedef enum {
    FORMAT_UNDEFINED, FORMAT_PEM, FORMAT_DER, FORMAT_P12
} FileFormat;

const char*
determine_filetype(FILE* fp, void** idata);

int 
extract_envelope(gpointer window,
		 void* idata,
		 const char* filetype,
		 STACK_OF(X509) **certs,
		 EVP_PKEY **pkey);
#endif
