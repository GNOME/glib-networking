sources = files(
  'openssl-module.c',
  'gtlsbackend-openssl.c',
  'gtlscertificate-openssl.c',
  'gtlsconnection-openssl.c',
  'gtlsserverconnection-openssl.c',
  'gtlsclientconnection-openssl.c',
  'gtlsdatabase-openssl.c',
  'gtlsfiledatabase-openssl.c',
  'gtlsbio.c',
  'openssl-util.c',
)

incs = [top_inc]

deps = [
  gio_dep,
  glib_dep,
  gmodule_dep,
  gobject_dep,
  tlsbase_dep,
  openssl_dep,
]

module = shared_module(
  'gioopenssl',
  sources: sources,
  include_directories: incs,
  dependencies: deps,
  link_args: module_ldflags,
  link_depends: symbol_map,
  name_suffix: module_suffix,
  install: true,
  install_dir: gio_module_dir,
)

if get_option('static_modules')
  static_library('gioopenssl',
    objects: module.extract_all_objects(),
    install: true,
    install_dir: gio_module_dir,
    link_whole: [tlsbase]
  )
  pkg.generate(module)
endif
