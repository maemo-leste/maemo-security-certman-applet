AC_INIT([maemo-security-certman-applet], 0.0.6)

# Initialize automake
AM_INIT_AUTOMAKE(AC_PACKAGE_NAME, AC_PACKAGE_VERSION)
AC_CONFIG_HEADERS(config.h)

LIBRARY_VERSION=0
AC_SUBST(LIBRARY_VERSION)

# Tests that source dir exists
AC_CONFIG_SRCDIR([src/applet_main.c])

# For automake: generate rules to reproduce config.h, if needed

AC_CANONICAL_HOST

AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LIBTOOL
AC_SUBST(LIBTOOL_DEPS)

AC_C_CONST
AC_HEADER_STDC

AC_CHECK_HEADERS([libintl.h])

AC_HEADER_STDBOOL

# Check module dependencies, will automatically include all needed
# compiler options to DEPS-variables, see src/Makefile.am for details

# certificate manager engine doesn't compile with stricter options, loose 
# them
#CFLAGS="$CFLAGS -Wall -Wno-format-y2k -ansi -Wmissing-prototypes -Wmissing-declarations -Werror -std=c99 -DDEBUG"
CFLAGS="$CFLAGS -Wall -Wno-format-y2k -ansi -Wmissing-prototypes \
-Wmissing-declarations -std=c99 -DDEBUG -D_REENTRANT"
AC_SUBST(CFLAGS)
                                                                                
PKG_CHECK_MODULES(GTK, gtk+-2.0 >= 2.4.0)
AC_SUBST(GTK_LIBS)
AC_SUBST(GTK_CFLAGS)
GTK_PREFIX=`pkg-config gtk+-2.0 --variable=prefix`
AC_SUBST(GTK_PREFIX)
                                                                                
PKG_CHECK_MODULES(DBUS, dbus-glib-1 >= 0.60)
AC_SUBST(DBUS_LIBS)
AC_SUBST(DBUS_CFLAGS)
                                                                                
PKG_CHECK_MODULES(GLIB, glib-2.0 >= 2.6.0)
AC_SUBST(GLIB_LIBS)
AC_SUBST(GLIB_CFLAGS)
                                                                                
PKG_CHECK_MODULES(OSSO, libosso >= 1.0.0)
AC_SUBST(OSSO_LIBS)
AC_SUBST(OSSO_CFLAGS)

PKG_CHECK_MODULES(HILDON, hildon-1 >= 1.0.0 hildon-control-panel >= 0.10.0 hildon-fm-2)
AC_SUBST(HILDON_LIBS)
AC_SUBST(HILDON_CFLAGS)
                                                                                
dnl PKG_CHECK_MODULES(GCONF, gconf-2.0 >= 2.6)
dnl AC_SUBST(GCONF_CFLAGS)
dnl AC_SUBST(GCONF_LIBS)

PKG_CHECK_MODULES(GNOME_VFS, gnome-vfs-2.0 >= 2.6 gnome-vfs-module-2.0 >= 2.6)
AC_SUBST(GNOME_VFS_CFLAGS)
AC_SUBST(GNOME_VFS_LIBS)

PKG_CHECK_MODULES(OPENSSL, [ openssl >= 0.9.8 ])
AC_SUBST(OPENSSL_CFLAGS)
AC_SUBST(OPENSSL_LIBS)

PKG_CHECK_MODULES(MAEMOSEC, maemosec >= 0.0.3 maemosec-certman >= 0.0.3 )
AC_SUBST(MAEMOSEC_CFLAGS)
AC_SUBST(MAEMOSEC_LIBS)

PKG_CHECK_MODULES(OSSOSETTINGS, osso-af-settings >= 0.8.1)
localedir=`pkg-config osso-af-settings --variable=localedir`

# Localisation-related
GETTEXT_PACKAGE=$PACKAGE
AC_SUBST(GETTEXT_PACKAGE)
# AM_GLIB_GNU_GETTEXT

AC_PATH_XTRA

AC_SUBST(X_LIBS)
AC_SUBST(X_CFLAGS)

hildoncpdesktopentrydir=`$PKG_CONFIG --variable=plugindesktopentrydir hildon-control-panel`
hildondesktopentrydir=${datadir}/applications/hildon
hildonpluginlibdir=`$PKG_CONFIG --variable=pluginlibdir hildon-control-panel`
hildonpixmapdir=${datadir}/icons/hicolor

AC_SUBST(localedir)
AC_SUBST(hildondesktopentrydir)
AC_SUBST(hildoncpdesktopentrydir)
AC_SUBST(hildonpluginlibdir)
AC_SUBST(appleticonsdir)
AC_SUBST(hildonpixmapdir)

# Mime stuff
dnl MIME-type registration check (2.6 / 2.8 version)
AC_PATH_PROG(UPDATE_MIME_DATABASE, update-mime-database, no)
AM_CONDITIONAL(HAVE_26_MIME, test x$UPDATE_MIME_DATABASE != xno)

AC_PATH_PROG(UPDATE_DESKTOP_DATABASE, update-desktop-database, no)
AM_CONDITIONAL(HAVE_28_MIME, test x$UPDATE_DESKTOP_DATABASE != xno)

dbuslibpathdir=`$PKG_CONFIG --variable=libdir dbus-1`
dbusconfdir=/etc/dbus-1/system.d
dbusservdir=${dbuslibpathdir}/dbus-1.0/services
AC_SUBST(dbuslibpathdir)
AC_SUBST(dbusconfdir)
AC_SUBST(dbusservdir)

AC_CONFIG_FILES(pkgconfig/maemosec-certman-applet.pc:pkgconfig/maemosec-certman-applet.pc.in)
AC_CONFIG_FILES(cfg/maemosec_certman_applet.desktop:cfg/maemosec_certman_applet.desktop.in)
AC_CONFIG_FILES(cfg/maemosec_certman_mimehandler.desktop:cfg/maemosec_certman_mimehandler.desktop.in)
AC_CONFIG_FILES(cfg/maemosec_certman.service:cfg/maemosec_certman.service.in)
AC_CONFIG_FILES(etc/maemosec_certman.schemas:etc/maemosec_certman.schemas.in)

AC_PROG_MAKE_SET
AC_OUTPUT([
Makefile
etc/Makefile
mime/Makefile
src/Makefile
])
