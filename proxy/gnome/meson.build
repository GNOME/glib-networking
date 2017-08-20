sources = files(
  'gproxyresolvergnome.c',
  'gnome-proxy-module.c'
)

deps = [
  gio_dep,
  glib_dep,
  gsettings_desktop_schemas_dep
]

shared_module(
  'giognomeproxy',
  sources: sources,
  include_directories: top_inc,
  dependencies: deps,
  link_args: module_ldflags,
  link_depends: symbol_map,
  install: true,
  install_dir: gio_module_dir
)

test_programs += [['gnome', deps]]
