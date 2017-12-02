sources = files(
  'gnutls-module.c',
  'gtlsbackend-gnutls.c',
  'gtlscertificate-gnutls.c',
  'gtlsclientconnection-gnutls.c',
  'gtlsconnection-gnutls.c',
  'gtlsdatabase-gnutls.c',
  'gtlsfiledatabase-gnutls.c',
  'gtlsinputstream-gnutls.c',
  'gtlsoutputstream-gnutls.c',
  'gtlsserverconnection-gnutls.c'
)

incs = [top_inc]

deps = [
  gio_dep,
  glib_dep,
  gnutls_dep
]

if enable_pkcs11_support
  sources += files(
    'gtlsbackend-gnutls-pkcs11.c',
    'gtlscertificate-gnutls-pkcs11.c',
    'gtlsdatabase-gnutls-pkcs11.c'
  )

  incs += tls_inc

  deps += libgiopkcs11_dep
endif

module = shared_module(
  'giognutls',
  sources: sources,
  include_directories: incs,
  dependencies: deps,
  link_args: module_ldflags,
  link_depends: symbol_map,
  install: true,
  install_dir: gio_module_dir
)

if get_option('static_modules')
  static_library('giognutls',
    objects: module.extract_all_objects(),
    install: true,
    install_dir: gio_module_dir
  )
endif
