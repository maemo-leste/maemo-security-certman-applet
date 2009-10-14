/* -*- mode:c; tab-width:4; c-basic-offset:4; -*- 
 *
 * This file is part of maemo-security-certman-applet
 *
 * Copyright (C) 2009 Nokia Corporation and/or its subsidiary(-ies).
 *
 * Contact: Juhani Mäkelä <ext-juhani.3.makela@nokia.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 *
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
