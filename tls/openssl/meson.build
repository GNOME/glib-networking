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

openssl_inc = include_directories('.')

deps = [
  gio_dep,
  glib_dep,
  gmodule_dep,
  gobject_dep,
  openssl_dep,
  tlsbase_dep,
]

if ['darwin', 'ios'].contains(host_system)
  deps += [
    security_dep,
  ]
endif

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
  # link_whole is a workaround for a meson bug
  # https://github.com/mesonbuild/meson/pull/3939
  static_library('gioopenssl',
    objects: module.extract_all_objects(),
    install: true,
    install_dir: gio_module_dir,
    link_whole: [tlsbase]
  )
  pkg.generate(module)
endif
