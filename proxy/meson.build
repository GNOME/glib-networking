if libproxy_dep.found()
  subdir('libproxy')
endif

if gsettings_desktop_schemas_dep.found()
  subdir('gnome')
endif

# FIXME: This ought to work on Windows.
# https://gitlab.gnome.org/GNOME/glib-networking/-/issues/185
if not ['windows'].contains(host_system)
  subdir('environment')
endif

if javascriptcoregtk_dep.found()
  subdir('pacrunner')
endif

subdir('tests')
