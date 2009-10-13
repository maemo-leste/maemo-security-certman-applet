/**
   @file i18n.h

   Internalization related header, which includes all gettext-stuff.
*/

#ifndef __I18N_H__
#define __I18N_H__

/*
 * Legacy language support domain, use this in stead
 * of PACKAGE when binding to text domain.
 */
#define LANGDOMAIN "osso-applet-certman"

#include <libintl.h>
#define _(a) dgettext(LANGDOMAIN, a)

#endif
