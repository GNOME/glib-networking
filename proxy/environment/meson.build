service_conf = configuration_data()
service_conf.set('libexecdir', libexecdir)

sources = files(
  'genvironmentproxyresolver.c',
  'environmentproxy-module.c'
)

deps = [
  gio_dep,
  glib_dep,
  gmodule_dep,
  gobject_dep
]

module = shared_module(
  'gioenvironmentproxy',
  sources: sources,
  include_directories: top_inc,
  dependencies: deps,
  c_args: '-DGENVIRONMENTPROXY_MODULE',
  link_args: module_ldflags,
  link_depends: symbol_map,
  name_suffix: module_suffix,
  install: true,
  install_dir: gio_module_dir
)

if get_option('static_modules')
  static_library('gioenvironmentproxy',
    objects: module.extract_all_objects(),
    install: true,
    install_dir: gio_module_dir
  )
  pkg.generate(module)
endif

proxy_test_programs += [['environment', 'environment', deps]]
