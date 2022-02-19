sources = files(
  'glibproxyresolver.c',
  'libproxy-module.c'
)

deps = [
  gio_dep,
  glib_dep,
  gmodule_dep,
  gobject_dep,
  libproxy_dep
]

module = shared_module(
  'giolibproxy',
  sources: sources,
  include_directories: top_inc,
  dependencies: deps,
  c_args: '-DGLIBPROXY_MODULE',
  link_args: module_ldflags,
  link_depends: symbol_map,
  name_suffix: module_suffix,
  install: true,
  install_dir: gio_module_dir
)

if get_option('static_modules')
  giolibproxy_lib = static_library('giolibproxy',
    objects: module.extract_all_objects(),
    install: true,
    install_dir: gio_module_dir
  )
  pkg.generate(module)

  giolibproxy_dep = declare_dependency(link_with: giolibproxy_lib)
  meson.override_dependency('giolibproxy', giolibproxy_dep)
endif

proxy_test_programs += [['environment', 'libproxy', deps]]

if meson.version().version_compare('>=0.58')
  env = environment()
  env.prepend('GIO_EXTRA_MODULES', meson.current_build_dir())
  meson.add_devenv(env)
endif
