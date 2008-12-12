SUBDIRS = src mime etc

EXTRA_DIST = \
	debian/* \
	src/cfg/maemosec_certman_applet.desktop.in \
	src/cfg/maemosec_certman_mimehandler.desktop.in \
	src/cfg/maemosec_certman.service.in \
	pkgconfig/maemosec-certman-applet.pc.in

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = pkgconfig/maemosec-certman-applet.pc

DISTCLEANFILES = \
	aclocal.m4 \
	config.h.in \
	Makefile.in \
	configure \
	autom4te.cache/* \
	debian/files \
	debian/*.debhelper \
	debian/*.substvars \
	config.sub \
	config.guess \
	ltmain.sh \
	libtool \
	depcomp \
	install-sh \
	missing \
	mkinstalldirs \
	src/cfg/*.desktop \
	etc/Makefile.in \
	mime/Makefile.in \
	src/Makefile.in \
	$(pkgconfig_DATA)


# What is this needed for?
#deb: dist
#	-mkdir $(top_builddir)/debian-build
#	cd $(top_builddir)/debian-build && tar zxf ../$(top_builddir)/$(PACKAGE)-$(VERSION).tar.gz
#	cd $(top_builddir)/debian-build/$(PACKAGE)-$(VERSION) && dpkg-buildpackage -rfakeroot 
#	-rm -rf $(top_builddir)/debian-build/$(PACKAGE)-$(VERSION)
