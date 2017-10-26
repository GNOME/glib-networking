project('glib-openssl', 'c',
        version: '2.50.5',
        license: 'LGPL2+',
        meson_version: '>= 0.41.0')

cc = meson.get_compiler('c')

glib_req = '2.46.0'
glib = dependency('glib-2.0', version: '>=' + glib_req)
gobject = dependency('gobject-2.0', version: '>=' + glib_req)
gio = dependency('gio-2.0', version: '>=' + glib_req)
giomoduledir = gio.get_pkgconfig_variable('giomoduledir')
gio_querymodules = find_program('gio-querymodules')

openssl = dependency('openssl')
# TODO: Handle finding on Win32

# Compiler flags
if cc.get_id() == 'msvc'
  # Make MSVC more pedantic, this is a recommended pragma list
  # from _Win32_Programming_ by Rector and Newcomer.  Taken from
  # glib's msvc_recommended_pragmas.h--please see that file for
  # the meaning of the warning codes used here
  test_cflags = [
    '-we4002', # too many actual parameters for macro
    '-we4003', # not enough actual parameters for macro
    '-w14010', # single-line comment contains line-continuation character
    '-we4013', # 'function' undefined; assuming extern returning int
    '-w14016', # no function return type; using int as default
    '-we4020', # too many actual parameters
    '-we4021', # too few actual parameters
    '-we4027', # function declared without formal parameter list
    '-we4029', # declared formal parameter list different from definition
    '-we4033', # 'function' must return a value
    '-we4035', # 'function' : no return value
    '-we4045', # array bounds overflow
    '-we4047', # different levels of indirection
    '-we4049', # terminating line number emission
    '-we4053', # an expression of type void was used as an operand
    '-we4071', # no function prototype given
    '-we4819', # the file contains a character that cannot be represented in the current code page
  ]
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
  ca_certificates = get_option('with-ca-certificates')
  if ca_certificates == 'no'
    message('CA certificates disabled')
  else
    if ca_certificates == ''
      detect_certificates = run_command(join_paths(meson.source_root(), 'build-aux', 'detect_certificates.py'))

      if detect_certificates.returncode() == 1
        error('Could not find certificates. Use -Dwith-ca-certificates=path to set, or -Dwith-ca-certificates=no to disable it')
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

meson.add_install_script(join_paths('build-aux', 'post_install.py'), giomoduledir)
