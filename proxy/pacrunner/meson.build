service_conf = configuration_data()
service_conf.set('libexecdir', libexecdir)

service = 'org.gtk.GLib.PACRunner.service'

configure_file(
  input: service + '.in',
  output: service,
  install: true,
  install_dir: join_paths(datadir, 'dbus-1', 'services'),
  configuration: service_conf
)

service = 'glib-pacrunner.service'

configure_file(
  input: service + '.in',
  output: service,
  install: true,
  install_dir: join_paths('lib', 'systemd', 'user'),
  configuration: service_conf
)

service_deps = [
  gio_dep,
  glib_dep,
  gobject_dep,
]

executable(
  'glib-pacrunner-service',
  'pacrunner-service.c',
  include_directories: top_inc,
  dependencies: service_deps,
  install: true,
  install_dir: libexecdir
)

worker_deps = [
  gio_dep,
  glib_dep,
  gobject_dep,
  javascriptcoregtk_dep,
  util_dep
]

executable(
  'glib-pacrunner-worker',
  'pacrunner-worker.c',
  include_directories: top_inc,
  dependencies: worker_deps,
  install: true,
  install_dir: libexecdir
)
