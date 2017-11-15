service_conf = configuration_data()
service_conf.set('libexecdir', libexecdir)

service = 'org.gtk.GLib.PACRunner.service'

configure_file(
  input: service + '.in',
  output: service,
  install: true,
  install_dir: dbus_service_dir,
  configuration: service_conf
)

service = 'glib-pacrunner.service'

configure_file(
  input: service + '.in',
  output: service,
  install: true,
  install_dir: systemd_user_unit_dir,
  configuration: service_conf
)

sources = files(
  'glibproxyresolver.c',
  'libproxy-module.c'
)

deps = [
  gio_dep,
  glib_dep,
  libproxy_dep
]

shared_module(
  'giolibproxy',
  sources: sources,
  include_directories: top_inc,
  dependencies: deps,
  c_args: '-DGLIBPROXY_MODULE',
  link_args: module_ldflags,
  link_depends: symbol_map,
  install: true,
  install_dir: gio_module_dir
)

sources = files(
  'glibproxyresolver.c',
  'glibpacrunner.c'
)

executable(
  'glib-pacrunner',
  sources,
  include_directories: top_inc,
  dependencies: deps,
  c_args: '-DGLIBPROXY_PACRUNNER',
  install: true,
  install_dir: libexecdir
)

proxy_test_programs += [['libproxy', deps]]
