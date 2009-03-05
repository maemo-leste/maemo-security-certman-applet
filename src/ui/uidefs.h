/* -*- mode:c++; tab-width:4; c-basic-offset:4; -*- */
/**
   @file uidefs.h

   Constants used in the UI.
   <p>
   Copyright (c) 2005 Nokia. All rights reserved.

   @author  Karoliina T. Salminen <karoliina.t.salminen@nokia.com>
*/

#ifndef __UIDEFS_H__
#define __UIDEFS_H__

#include <hildon/hildon.h>
#include <hildon/hildon-help.h>

/* Size for the main dialog */
#define MIN_WIDTH               592
#define MIN_HEIGHT              332
#define MAX_WIDTH               800
#define MAX_HEIGHT              332

/* Size for the details dialog */
#define DETAILS_MIN_WIDTH       482
#define DETAILS_MIN_HEIGHT      338
#define DETAILS_MAX_WIDTH       800
#define DETAILS_MAX_HEIGHT      338

/* Size for the trust dialog */
#define TRUST_MIN_WIDTH         352
#define TRUST_MIN_HEIGHT        180
#define TRUST_MAX_WIDTH         800
#define TRUST_MAX_HEIGHT        338

/* Size for the import dialog */
#define IMPORT_MIN_WIDTH        462
#define IMPORT_MIN_HEIGHT       -1
#define IMPORT_MAX_WIDTH        800
#define IMPORT_MAX_HEIGHT       -1

/* Size for the export dialog */
#define EXPORT_MIN_WIDTH        282
#define EXPORT_MIN_HEIGHT       180
#define EXPORT_MAX_WIDTH        800
#define EXPORT_MAX_HEIGHT       180

/* Size for the change password dialog */
#define PASSWD_MIN_WIDTH        352
#define PASSWD_MIN_HEIGHT       -1
#define PASSWD_MAX_WIDTH        800
#define PASSWD_MAX_HEIGHT       -1

/* Size for the select default key dialog */
#define SELECT_MIN_WIDTH        282
#define SELECT_MIN_HEIGHT       300
#define SELECT_MAX_WIDTH        800
#define SELECT_MAX_HEIGHT       300

/* Other UI defs */
#define CERT_VALID_PIXMAP       "qgn_list_cpa_valid"
#define CERT_INVALID_PIXMAP     "qgn_list_cpa_invalid"
#define CERT_WARNING_PIXMAP     "qgn_list_cpa_invalid"

#define DEFAULT_SUFFIX          ".cer"
#define PEM_SUFFIX              ".pem"
#define DER_SUFFIX              ".der"
#define PFX_SUFFIX              ".pfx"
#define P12_SUFFIX              ".p12"

#define DEFAULT_SUFFIX01        ".crt"

#define CERT_MIMETYPE1          "application/x-x509-user-cert"
#define CERT_MIMETYPE2          "application/x-x509-ca-cert"
#define CERT_MIMETYPE3          "application/x-x509-email-cert"

#define LABEL_ID                50000

/* Buffer size for various string routines */
#define BUFSIZE                 256

#define ICONSIZE                HILDON_ICON_PIXEL_SIZE_SMALL
#define REFRESH_INTERVAL        500

#define NAME_COL_WIDTH          340
#define ISSUE_COL_WIDTH         170
#define PURPOSE_COL_WIDTH       120

typedef enum {AUTH_USER, AUTH_ROOT} AuthType;

/* Response types */
typedef enum
{
    CM_RESPONSE_DELETE = 1,
    CM_RESPONSE_TRUST,
    CM_RESPONSE_PASSWORD,
    CM_RESPONSE_CLOSE,
    CM_RESPONSE_DETAILS,
    CM_RESPONSE_INSTALL
} CMResponseType;

/* Certificate list colums */
enum {
    MAIN_NAME_COL = 0,
    MAIN_PURPOSE_COL,
    MAIN_ID_COL,
    MAIN_DOMAIN_COL,
	MAIN_DOM_TYPE_COL,
    MAIN_NUM_COLUMNS
};

/* Certificate chain list columns */
enum {
    CHAIN_IMG_COL = 0,
    CHAIN_NAME_COL,
    CHAIN_ID_COL,
    CHAIN_NUM_COLUMNS
};

/* List for select default key */
enum {
    SELECT_NAME_COL = 0,
    SELECT_ID_COL,
    SELECT_NUM_COLUMNS
};

struct pkcs12_target {
	gchar* symbolic_name;
	gchar* user_domain;
	gchar* ca_domain;
};

const struct pkcs12_target pkcs12_targets [];

#endif
