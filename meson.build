project(
  'glib-networking', 'c',
  version: '2.66.0',
  license: 'LGPL2.1+',
  meson_version: '>= 0.50.0',
  default_options: ['c_std=c99']
)

prefix = get_option('prefix')
datadir = join_paths(prefix, get_option('datadir'))
libdir = join_paths(prefix, get_option('libdir'))
libexecdir = join_paths(prefix, get_option('libexecdir'))
localedir = join_paths(prefix, get_option('localedir'))

installed_tests_metadir = join_paths(datadir, 'installed-tests', meson.project_name())
installed_tests_execdir = join_paths(libexecdir, 'installed-tests', meson.project_name())

cc = meson.get_compiler('c')
host_system = host_machine.system()

config_h = configuration_data()

config_h.set_quoted('GETTEXT_PACKAGE', meson.project_name())

# compiler flags
common_flags = [
  '-DHAVE_CONFIG_H',
  '-DG_LOG_DOMAIN="GLib-Net"',
  '-DG_LOG_USE_STRUCTURED',
  '-DLOCALE_DIR="@0@"'.format(localedir),
  '-DG_DISABLE_DEPRECATED',
  '-DGLIB_VERSION_MIN_REQUIRED=GLIB_VERSION_2_56'
]

add_project_arguments(common_flags, language: 'c')

cflags = cc.get_supported_arguments(['-Werror=declaration-after-statement',
                                     '-Werror=implicit-function-declaration'])
add_project_arguments(cflags, language: 'c')

symbol_map = join_paths(meson.current_source_dir(), meson.project_name() + '.map')

module_ldflags = []

if host_system.contains('linux')
  test_ldflag = '-Wl,--version-script,' + symbol_map
  module_ldflags += cc.get_supported_link_arguments(test_ldflag)
endif

# *** Check GLib GIO        ***
glib_dep = dependency('glib-2.0', version: '>= 2.65.1',
  fallback: ['glib', 'libglib_dep'])
gio_dep = dependency('gio-2.0',
  fallback: ['glib', 'libgio_dep'])
gobject_dep = dependency('gobject-2.0',
  fallback: ['glib', 'libgobject_dep'])
gmodule_dep = dependency('gmodule-2.0',
  fallback: ['glib', 'libgmodule_dep'])

if glib_dep.type_name() == 'internal'
  glib_proj = subproject('glib')
  gio_module_dir = glib_proj.get_variable('glib_giomodulesdir')
else
  gio_module_dir = gio_dep.get_pkgconfig_variable('giomoduledir',
                                                  define_variable: ['libdir', join_paths(prefix, libdir)])
endif

assert(gio_module_dir != '', 'GIO_MODULE_DIR is missing from gio-2.0.pc')

# *** Checks for LibProxy   ***
libproxy_dep = dependency('libproxy-1.0', version: '>= 0.3.1', required: get_option('libproxy'))

# *** Checks for GNOME      ***
gsettings_desktop_schemas_dep = dependency('gsettings-desktop-schemas', required: get_option('gnome_proxy'))

backends = []

# *** Checks for GnuTLS     ***
gnutls_dep = dependency('gnutls', version: '>= 3.6.5', required: get_option('gnutls'))

if gnutls_dep.found()
  backends += ['gnutls']
endif

# *** Checks for OpenSSL    ***
openssl_option = get_option('openssl')
if openssl_option.disabled()
  openssl_dep = []
else
  # XXX: https://github.com/mesonbuild/meson/issues/2945
  openssl_dep = dependency('openssl', required: false)
  if openssl_dep.found()
    backends += ['openssl']
  else
    # MSVC builds of OpenSSL does not generate pkg-config files,
    # so we check for it manually here in this case, if we can't find those files
    # Based on the CMake check for OpenSSL in CURL's CMakeLists.txt,
    # on which headers we should check for

    # OpenSSL's MSVC NMake Makefiles prepends the library filenames with 'lib',
    # so we must prepend the libraries with 'lib' on MSVC, except for the pre-1.1.x
    # ssleay32.lib
    openssl_lib_prefix = ''
    if cc.get_argument_syntax() == 'msvc'
      openssl_lib_prefix = 'lib'
    endif

    openssl_headers = []
    foreach h : ['crypto.h', 'engine.h', 'err.h', 'pem.h',
                 'rsa.h', 'ssl.h', 'x509.h', 'rand.h', 'tls1.h']
      openssl_headers += 'openssl/' + h
    endforeach

    # OpenSSL 1.1.x and 1.0.x (or earlier) have different .lib names,
    # so we need to look for the correct pair

    # Find either libcrypto.lib (1.1.x) or libeay32.lib (1.0.x or earlier) first
    libcrypto_dep = cc.find_library('@0@crypto'.format(openssl_lib_prefix), required: false)
    if libcrypto_dep.found()
      libssl = '@0@ssl'.format(openssl_lib_prefix)
    else
      libcrypto_dep = cc.find_library('@0@eay32'.format(openssl_lib_prefix), required: openssl_option)
      libssl = 'ssleay32'
    endif

    if libcrypto_dep.found()
      # Find the corresponding SSL library depending on which crypto .lib we found
      libssl_dep = cc.find_library(libssl, required: openssl_option, has_headers: openssl_headers)
    endif

    if libcrypto_dep.found() and libssl_dep.found()
      openssl_dep = [libcrypto_dep, libssl_dep]
      backends += ['openssl']
    endif
  endif
endif

if backends.length() == 0
  error('No TLS backends enabled. Please enable at least one TLS backend')
endif

configure_file(
  output: 'config.h',
  configuration: config_h
)

gnome = import('gnome')
i18n = import('i18n')
pkg = import('pkgconfig')

po_dir = join_paths(meson.source_root(), 'po')

top_inc = include_directories('.')
tls_inc = include_directories('tls')

subdir('po')

enable_installed_tests = get_option('installed_tests')
test_template = files('template.test.in')

module_suffix = []
# Keep the autotools convention for shared module suffix because GModule
# depends on it: https://gitlab.gnome.org/GNOME/glib/issues/520
if ['darwin', 'ios'].contains(host_system)
  module_suffix = 'so'
endif

if libproxy_dep.found() or gsettings_desktop_schemas_dep.found()
  proxy_test_programs = []

  if libproxy_dep.found()
    subdir('proxy/libproxy')
  endif

  if gsettings_desktop_schemas_dep.found()
    subdir('proxy/gnome')
  endif

  subdir('proxy/tests')
endif

subdir('tls/base')

if gnutls_dep.found()
  subdir('tls/gnutls')
endif

if backends.contains('openssl')
  subdir('tls/openssl')
endif

subdir('tls/tests')

# Will automatically pick it up from the cross file if defined
gio_querymodules = find_program('gio-querymodules', required : false)
if gio_querymodules.found()
  meson.add_install_script('meson_post_install.py', gio_querymodules.path(), gio_module_dir)
endif

output = '\n\n'
output += '  gnutls support:      ' + backends.contains('gnutls').to_string() + '\n'
output += '  openssl support:     ' + backends.contains('openssl').to_string() + '\n'
output += '  libproxy support:    ' + libproxy_dep.found().to_string() + '\n'
output += '  GNOME proxy support: ' + gsettings_desktop_schemas_dep.found().to_string() + '\n'
message(output)
