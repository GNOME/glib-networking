project('glib-openssl', 'c',
        version: '2.50.8',
        license: 'LGPL2+',
        meson_version: '>= 0.41.0')

cc = meson.get_compiler('c')

glib_req = '2.46.0'
glib = dependency('glib-2.0', version: '>=' + glib_req)
gobject = dependency('gobject-2.0', version: '>=' + glib_req)
gio = dependency('gio-2.0', version: '>=' + glib_req)

gio_module_dir = gio.get_pkgconfig_variable('giomoduledir',
                                            define_variable: ['libdir', get_option('libdir')])
assert(gio_module_dir != '', 'GIO_MODULE_DIR is missing from gio-2.0.pc')

gio_querymodules = find_program('gio-querymodules')

# MSVC builds of OpenSSL does not generate pkg-config files,
# so we check for it manually here in this case, if we can't find those files
openssl = dependency('openssl', required: cc.get_id() != 'msvc')

if not openssl.found()
  # Based on the CMake check for OpenSSL in CURL's CMakeLists.txt,
  # on which headers we should check for
  cc.has_header('openssl/crypto.h')
  cc.has_header('openssl/engine.h')
  cc.has_header('openssl/err.h')
  cc.has_header('openssl/pem.h')
  cc.has_header('openssl/rsa.h')
  cc.has_header('openssl/ssl.h')
  cc.has_header('openssl/x509.h')
  cc.has_header('openssl/rand.h')
  cc.has_header('openssl/tls1.h')

  # OpenSSL 1.1.x and 1.0.x (or earlier) have different .lib names,
  # so we need to look for the correct pair

  # Find either libcrypto.lib (1.1.x) or libeay32.lib (1.0.x or earlier) first
  libcrypto = cc.find_library('libcrypto', required: false)
  if not libcrypto.found()
    libeay = cc.find_library('libeay32')
  endif

  # Find the corresponding SSL library depending on which crypto .lib we found
  if libcrypto.found()
    libssl = cc.find_library('libssl')
  elif libeay.found()
    ssleay = cc.find_library('ssleay32')
  endif

  # Now set the openssl dependency to the corresponding pair of .lib files that we found
  if libcrypto.found()
    openssl = [libcrypto, libssl]
  else
    openssl = [libeay, ssleay]
  endif
endif

# Compiler flags
if cc.get_id() == 'msvc'
  # Make MSVC more pedantic, this is a recommended pragma list
  # from _Win32_Programming_ by Rector and Newcomer.  Taken from
  # glib's msvc_recommended_pragmas.h--please see that file for
  # the meaning of the warning codes used here
  test_cflags = []
  add_project_arguments('/FImsvc_recommended_pragmas.h', language : 'c')
else
  test_cflags = [
    '-ffast-math',
    '-fstrict-aliasing',
    '-Wpointer-arith',
    '-Wmissing-declarations',
    '-Wformat=2',
    '-Wstrict-prototypes',
    '-Wmissing-prototypes',
    '-Wnested-externs',
    '-Wold-style-definition',
    '-Wdeclaration-after-statement',
    '-Wunused',
    '-Wuninitialized',
    '-Wshadow',
    '-Wmissing-noreturn',
    '-Wmissing-format-attribute',
    '-Wredundant-decls',
    '-Wlogical-op',
    '-Wcast-align',
    '-Wno-unused-local-typedefs',
    '-Werror=implicit',
    '-Werror=init-self',
    '-Werror=main',
    '-Werror=missing-braces',
    '-Werror=return-type',
    '-Werror=array-bounds',
    '-Werror=write-strings'
  ]
endif
common_flags = []
foreach cflag: test_cflags
  if cc.has_argument(cflag)
    common_flags += [ cflag ]
  endif
endforeach

extra_args= []
# Detect and set symbol visibility
if cc.get_id() == 'msvc'
  extra_args += ['-D_GLIB_EXTERN=__declspec (dllexport) extern']
endif

config_h = configuration_data()
config_h.set_quoted('GETTEXT_PACKAGE', meson.project_name())
config_h.set_quoted('LOCALE_DIR', join_paths(get_option('prefix'), get_option('localedir')))
config_h.set('G_DISABLE_DEPRECATED', true)
config_h.set_quoted('G_LOG_DOMAIN', 'GLib-OpenSSL')

if host_machine.system() != 'windows'
  ca_certificates = get_option('ca_certificates')
  if ca_certificates == 'no'
    message('CA certificates disabled')
  else
    if ca_certificates == ''
      detect_certificates = run_command(join_paths(meson.source_root(), 'build-aux', 'detect_certificates.py'))

      if detect_certificates.returncode() == 1
        error('Could not find certificates. Use -Dca_certificates=path to set, or -Dca_certificates=no to disable it')
      endif

      ca_certificates = detect_certificates.stdout().strip()
    endif

    message('CA certificates: ' + ca_certificates)

    config_h.set_quoted('GTLS_SYSTEM_CA_FILE', ca_certificates)
  endif
endif

configure_file(output: 'config.h',
               configuration: config_h)
config_h_include = include_directories('.')

subdir('tls/base')
subdir('tls/openssl')
subdir('tls/tests')
subdir('po')

meson.add_install_script(join_paths('build-aux', 'post_install.py'), gio_module_dir)
