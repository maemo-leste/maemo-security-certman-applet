# Makefile.am for CPAs

INCLUDES = $(HILDON_CFLAGS) -DLOCALEDIR=\"$(localedir)\" \
        $(OSSO_CFLAGS)  -DPREFIX=\"$(prefix)\" -DBIN_DIR=\"$(bindir)\" \
	$(GCONF_CFLAGS) $(OPENSSL_CFLAGS) $(MAEMOSEC_FLAGS) \
	$(X_CFLAGS) $(GNOME_VFS_CFLAGS) $(COMAPP_CFLAGS)

bin_PROGRAMS = maemosec_certman_service

maemosec_certman_service_LDADD = $(OSSO_LIBS) $(HILDON_LIBS) $(GNOME_VFS_LIBS) $(X_LIBS) \
		   $(MAEMOSEC_LIBS) $(X11_LIBS) $(COMAPP_LIBS) libmaemosec_certman_dialogs.la

maemosec_certman_service_SOURCES = maemosec_certman_service.c

lib_LTLIBRARIES = libmaemosec_certman_dialogs.la

libmaemosec_certman_dialogs_la_LDFLAGS = -module -no-undefined -version-info $(LIBRARY_VERSION)

libmaemosec_certman_dialogs_la_LIBADD = $(HILDON_LIBS) $(OSSO_LIBS) $(GCONF_LIBS) \
			 $(OPENSSL_LIBS) $(MAEMOSEC_LIBS) $(GNOME_VFS_LIBS) $(X_LIBS) $(X11_LIBS) $(COMAPP_LIBS)

hildonpluginlib_LTLIBRARIES = libmaemosec_certman_applet.la

libmaemosec_certman_applet_la_LDFLAGS = -module -avoid-version -no-undefined

libmaemosec_certman_applet_la_LIBADD = $(HILDON_LIBS) $(OSSO_LIBS) $(GCONF_LIBS) \
			 $(OPENSSL_LIBS) $(MAEMOSEC_LIBS) $(X11_LIBS) $(COMAPP_LIBS) libmaemosec_certman_dialogs.la

LDADD = libmaemosec_certman_dialogs.la

include_HEADERS = osso-applet-certman.h

libmaemosec_certman_applet_la_SOURCES =	applet_main.c

libmaemosec_certman_dialogs_la_SOURCES = \
	cm_dialogs.h cm_dialogs.c \
	cm_envelopes.h cm_envelopes.c
	i18n.h osso-applet-certman.h 
