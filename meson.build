project(
  'glib-networking', 'c',
  version: '2.59.2',
  license: 'LGPL2.1+',
  meson_version: '>= 0.47.0',
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
host_system = host_machine.system()

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

if host_system.contains('linux')
  test_ldflag = '-Wl,--version-script,' + symbol_map
  module_ldflags += cc.get_supported_link_arguments(test_ldflag)
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
                                                  define_variable: ['libdir', join_paths(prefix, libdir)])
endif

assert(gio_module_dir.startswith(prefix), 'GIO_MODULE_DIR is missing from gio-2.0.pc')

# *** Checks for LibProxy   ***
libproxy_dep = dependency('libproxy-1.0', version: '>= 0.3.1', required: get_option('libproxy'))

# *** Checks for GNOME      ***
gsettings_desktop_schemas_dep = dependency('gsettings-desktop-schemas', required: get_option('gnome_proxy'))

backends = []

# *** Checks for GnuTLS     ***
gnutls_dep = dependency('gnutls', version: '>= 3.4.6', required: get_option('gnutls'))

if gnutls_dep.found()
  backends += ['gnutls']
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

if gnutls_dep.found()
  subdir('tls/gnutls')
endif

subdir('tls/tests')

# Will automatically pick it up from the cross file if defined
gio_querymodules = find_program('gio-querymodules', required : false)
if gio_querymodules.found()
  meson.add_install_script('meson_post_install.py', gio_querymodules.path(), gio_module_dir)
endif

output = '\n\n'
output += '  GnuTLS support:      ' + libproxy_dep.found().to_string() + '\n'
output += '  libproxy support:    ' + libproxy_dep.found().to_string() + '\n'
output += '  GNOME proxy support: ' + gsettings_desktop_schemas_dep.found().to_string() + '\n'
message(output)
