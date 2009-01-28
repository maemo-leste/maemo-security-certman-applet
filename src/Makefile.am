# Makefile.am for CPAs

# These come from configure-script's module dependency checks
INCLUDES = $(HILDON_CFLAGS) -DLOCALEDIR=\"$(localedir)\" \
        $(OSSO_CFLAGS)  -DPREFIX=\"$(prefix)\" -DBIN_DIR=\"$(bindir)\" \
	$(GCONF_CFLAGS) $(OPENSSL_CFLAGS) $(MAEMOSEC_FLAGS) \
	$(X_CFLAGS)

hildoncpdesktopentry_DATA = cfg/maemosec_certman_applet.desktop

hildondesktopentry_DATA = cfg/maemosec_certman_mimehandler.desktop

servicefiledir=$(datadir)/dbus-1/services
servicefile_DATA = cfg/maemosec_certman.service


bin_PROGRAMS = maemosec_certman_service

maemosec_certman_service_LDADD = $(OSSO_LIBS) $(HILDON_LIBS) $(GNOME_VFS_LIBS) $(X_LIBS) \
		   $(MAEMOSEC_LIBS) libmaemosec_certman_dialogs.la
maemosec_certman_service_SOURCES = srv/cm_service.c srv/dbus.c srv/dbus.h


lib_LTLIBRARIES = libmaemosec_certman_dialogs.la

libmaemosec_certman_dialogs_la_LDFLAGS = -module -no-undefined -version-info $(LIBRARY_VERSION)

libmaemosec_certman_dialogs_la_LIBADD = $(HILDON_LIBS) $(OSSO_LIBS) $(GCONF_LIBS) \
			 $(OPENSSL_LIBS) $(MAEMOSEC_LIBS) $(GNOME_VFS_LIBS) $(X_LIBS)


hildonpluginlib_LTLIBRARIES = libmaemosec_certman_applet.la

libmaemosec_certman_applet_la_LDFLAGS = -module -avoid-version -no-undefined 

libmaemosec_certman_applet_la_LIBADD = $(HILDON_LIBS) $(OSSO_LIBS) $(GCONF_LIBS) \
			 $(OPENSSL_LIBS) $(MAEMOSEC_LIBS) libmaemosec_certman_dialogs.la
LDADD = libmaemosec_certman_dialogs.la


include_HEADERS = ui/osso-applet-certman.h

# certmanincludedir = $(includedir)
# certmaninclude_HEADERS = ui/osso-applet-certman.h

libmaemosec_certman_applet_la_SOURCES = \
	applet_start.c applet_start.h \
	i18n.h ui/uidefs.h \
	ui/interface.c ui/interface.h \
	ui/callbacks.c ui/callbacks.h \
	ui/uiutils.h

libmaemosec_certman_dialogs_la_SOURCES = \
	i18n.h ui/uidefs.h \
	ui/uiutils.c ui/uiutils.h \
	ui/details.c \
	ui/password.c \
	ui/trust.c \
	ui/osso-applet-certman.h \
	ui/importexport.c
