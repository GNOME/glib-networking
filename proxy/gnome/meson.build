sources = files(
  'gproxyresolvergnome.c',
  'gnome-proxy-module.c'
)

deps = [
  gio_dep,
  glib_dep,
  gmodule_dep,
  gobject_dep,
  gsettings_desktop_schemas_dep
]

module = shared_module(
  'giognomeproxy',
  sources: sources,
  include_directories: top_inc,
  dependencies: deps,
  link_args: module_ldflags,
  link_depends: symbol_map,
  name_suffix: module_suffix,
  install: true,
  install_dir: gio_module_dir
)

if get_option('static_modules')
  static_library('giognomeproxy',
    objects: module.extract_all_objects(),
    install: true,
    install_dir: gio_module_dir
  )
  pkg.generate(module)
endif

proxy_test_programs += [['gnome', deps]]
