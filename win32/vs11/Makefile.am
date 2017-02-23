EXTRA_DIST =	\
	glib-openssl.sln			\
	glib-openssl-build-defines.props	\
	glib-openssl-gen-srcs.props		\
	glib-openssl-install.props		\
	glib-openssl-version-paths.props	\
	glib-openssl-install.vcxproj		\
	glib-openssl-prepbuild.vcxproj	\
	libgioopenssl.vcxproj			\
	libgioopenssl.vcxproj.filters		\
	tlsbase.vcxproj			\
	tlsbase.vcxproj.filters

DISTCLEANFILES = $(EXTRA_DIST)

MSVC_BASE_VER = 10
MSVC_BASE_VER_LONG = 2010
MSVC_VER = 11
MSVC_VER_LONG = 2012

include $(top_srcdir)/win32/Makefile-newvs.am
