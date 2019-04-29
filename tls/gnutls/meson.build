sources = files(
  'gnutls-module.c',
  'gtlsbackend-gnutls.c',
  'gtlscertificate-gnutls.c',
  'gtlsclientconnection-gnutls.c',
  'gtlsconnection-gnutls.c',
  'gtlsdatabase-gnutls.c',
  'gtlsfiledatabase-gnutls.c',
  'gtlsserverconnection-gnutls.c'
)

incs = [top_inc]

deps = [
  gio_dep,
  glib_dep,
  gmodule_dep,
  gobject_dep,
  gnutls_dep
]

module = shared_module(
  'giognutls',
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
  static_library('giognutls',
    objects: module.extract_all_objects(),
    install: true,
    install_dir: gio_module_dir
  )
  pkg.generate(module)
endif
