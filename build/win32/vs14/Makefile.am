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

MSVC_VER = 14
MSVC_FORMAT_VER=12
MSVC_VER_LONG = 14

include $(top_srcdir)/build/Makefile-newvs.am
