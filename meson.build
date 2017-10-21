project(
  'glib-networking', 'c',
  version: '2.54.0',
  license: 'LGPL2.1+',
  meson_version: '>= 0.43.0'
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
  '-DGLIB_VERSION_MIN_REQUIRED=GLIB_VERSION_2_46'
]

add_project_arguments(common_flags, language: 'c')

symbol_map = join_paths(meson.current_source_dir(), meson.project_name() + '.map')

module_ldflags = []

if host_machine.system().contains('linux')
  test_ldflag = '-Wl,--version-script,' + symbol_map

  module_ldflags += cc.get_supported_arguments(test_ldflag)
endif

# *** Check GLib GIO        ***
glib_dep = dependency('glib-2.0', version: '>= 2.46.0')
gio_dep = dependency('gio-2.0')

gio_module_dir = gio_dep.get_pkgconfig_variable('giomoduledir')
assert(gio_module_dir != '', 'GIO_MODULE_DIR is missing from gio-2.0.pc')

# *** Checks for LibProxy   ***
have_libproxy = false

enable_libproxy = get_option('libproxy_backend')
if enable_libproxy != 'no'
  libproxy_dep = dependency('libproxy-1.0', version: '>= 0.3.1', required: (enable_libproxy == 'yes'))
  have_libproxy = libproxy_dep.found()
endif

# *** Checks for GNOME proxy backend ***
have_gnome_proxy = false

enable_gnome_proxy = get_option('gnome_proxy_backend')
if enable_gnome_proxy != 'no'
  gsettings_desktop_schemas_dep = dependency('gsettings-desktop-schemas', required: (enable_gnome_proxy == 'yes'))
  have_gnome_proxy = gsettings_desktop_schemas_dep.found()
endif

# *** Checks for GNUTLS     ***
tls_support = []

enable_tls_support = get_option('tls_support')
if enable_tls_support
  gnutls_dep = dependency('gnutls', version: '>= 3.0')
  tls_support += ['gnutls']
  pkcs_support = []

  msg = 'location of system Certificate Authority list: '
  res = run_command(find_program('find-ca-certificates'), get_option('ca_certificates_path'))
  assert(res.returncode() == 0, msg + ' could not find any CA certificate store. Use -Dca_certificates_path=PATH to set, or -Dtls_support=no to disable')
  ca_certificates_path = res.stdout().strip()
  message(msg + ca_certificates_path)

  # *** Checks for pkcs11    ***
  have_pkcs11 = false

  enable_pkcs11_support = get_option('pkcs11_support')
  if enable_pkcs11_support != 'no'
    pkcs11_dep = dependency('p11-kit-1', version: '>= 0.8', required: (enable_pkcs11_support == 'yes'))
    have_pkcs11 = pkcs11_dep.found()
    if have_pkcs11
      tls_support += ['gnutls-pkcs11']
      pkcs_support += ['p11-kit']
    endif

    config_h.set('HAVE_PKCS11', have_pkcs11,
                 description: 'Building with PKCS#11 support')
  endif
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

subdir('po')

enable_installed_tests = get_option('installed_tests')
test_template = files('template.test.in')

if have_libproxy or have_gnome_proxy
  test_programs = []

  if have_libproxy
    subdir('proxy/libproxy')
  endif

  if have_gnome_proxy
    subdir('proxy/gnome')
  endif

  subdir('proxy/tests')
endif

if enable_tls_support
  if have_pkcs11
    tls_inc = include_directories('tls')

    subdir('tls/pkcs11')
  endif

  subdir('tls/gnutls')
  subdir('tls/tests')
endif

meson.add_install_script('meson_post_install.py', gio_module_dir)

output = '\n\n  Proxy support:     ' + have_libproxy.to_string() + '\n'
output += '  TLS support:       ' + ' '.join(tls_support) + '\n'

if tls_support.length() > 0
  output += '  PKCS#11 Support:   ' + ' '.join(pkcs_support) + '\n'
  output += '  TLS CA file:       ' + ca_certificates_path + '\n'
endif
message(output)
