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

if get_option('static_modules') or get_option('default_library') != 'shared'
  giognomeproxy_lib = static_library('giognomeproxy',
    objects: module.extract_all_objects(),
    install: true,
    install_dir: gio_module_dir
  )
  pkg.generate(module)

  giognomeproxy_dep = declare_dependency(link_with: giognomeproxy_lib)
  meson.override_dependency('giognomeproxy', giognomeproxy_dep)
endif

proxy_test_programs += [['gnome', 'gnome', deps]]

if meson.version().version_compare('>=0.58')
  env = environment()
  env.prepend('GIO_EXTRA_MODULES', meson.current_build_dir())
  meson.add_devenv(env)
endif
