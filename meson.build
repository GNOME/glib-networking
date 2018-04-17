project(
  'glib-networking', 'c',
  version: '2.55.90',
  license: 'LGPL2.1+',
  meson_version: '>= 0.43.0',
  default_options: ['c_std=c11']
)

prefix = get_option('prefix')
datadir = join_paths(prefix, get_option('datadir'))
libdir = join_paths(prefix, get_option('libdir'))
libexecdir = join_paths(prefix, get_option('libexecdir'))
localedir = join_paths(prefix, get_option('localedir'))

installed_tests_metadir = join_paths(datadir, 'installed-tests', meson.project_name())
installed_tests_execdir = join_paths(libexecdir, 'installed-tests', meson.project_name())

cc = meson.get_compiler('c')

config_h = configuration_data()

config_h.set_quoted('GETTEXT_PACKAGE', meson.project_name())

# compiler flags
common_flags = [
  '-DHAVE_CONFIG_H',
  '-DG_LOG_DOMAIN="GLib-Net"',
  '-DLOCALE_DIR="@0@"'.format(localedir),
  '-DG_DISABLE_DEPRECATED',
  '-DGLIB_VERSION_MIN_REQUIRED=GLIB_VERSION_2_56'
]

add_project_arguments(common_flags, language: 'c')

symbol_map = join_paths(meson.current_source_dir(), meson.project_name() + '.map')

module_ldflags = []

if host_machine.system().contains('linux')
  test_ldflag = '-Wl,--version-script,' + symbol_map

  module_ldflags += cc.get_supported_arguments(test_ldflag)
endif

# *** Check GLib GIO        ***
glib_dep = dependency('glib-2.0', version: '>= 2.55.1',
  fallback: ['glib', 'libglib_dep'])
gio_dep = dependency('gio-2.0',
  fallback: ['glib', 'libgio_dep'])
gobject_dep = dependency('gio-2.0',
  fallback: ['glib', 'libgobject_dep'])
gmodule_dep = dependency('gmodule-2.0',
  fallback: ['glib', 'libgmodule_dep'])

if glib_dep.type_name() == 'internal'
  glib_proj = subproject('glib')
  gio_module_dir = glib_proj.get_variable('glib_giomodulesdir')
else
  gio_module_dir = gio_dep.get_pkgconfig_variable('giomoduledir',
                                                  define_variable: ['prefix', prefix])
endif

assert(gio_module_dir != '', 'GIO_MODULE_DIR is missing from gio-2.0.pc')

# *** Checks for LibProxy   ***
enable_libproxy_support = get_option('libproxy_support')
if enable_libproxy_support
  libproxy_dep = dependency('libproxy-1.0', version: '>= 0.3.1', required: true)
endif

# *** Checks for GNOME      ***
enable_gnome_proxy_support = get_option('gnome_proxy_support')
if enable_gnome_proxy_support
  gsettings_desktop_schemas_dep = dependency('gsettings-desktop-schemas', required: true)
endif

# *** Checks for GnuTLS     ***
gnutls_dep = dependency('gnutls', version: '>= 3.4', required: true)

# *** Checks for p11-kit  ***
enable_pkcs11_support = get_option('pkcs11_support')
if enable_pkcs11_support
  pkcs11_dep = dependency('p11-kit-1', version: '>= 0.20', required: true)

  config_h.set('HAVE_PKCS11', enable_pkcs11_support,
               description: 'Building with PKCS#11 support')
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

if enable_libproxy_support or enable_gnome_proxy_support
  proxy_test_programs = []

  if enable_libproxy_support
    subdir('proxy/libproxy')
  endif

  if enable_gnome_proxy_support
    subdir('proxy/gnome')
  endif

  subdir('proxy/tests')
endif

if enable_pkcs11_support
  subdir('tls/pkcs11')
endif

subdir('tls/gnutls')
subdir('tls/tests')

meson.add_install_script('meson_post_install.py', gio_module_dir)

output = '\n\n  libproxy support:    ' + enable_libproxy_support.to_string() + '\n'
output += '  GNOME proxy support: ' + enable_gnome_proxy_support.to_string() + '\n'
output += '  PKCS#11 support:     ' + enable_pkcs11_support.to_string() + '\n'
message(output)
