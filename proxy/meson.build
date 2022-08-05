if libproxy_dep.found()
  subdir('libproxy')
endif

if gsettings_desktop_schemas_dep.found()
  subdir('gnome')
endif

if environment_proxy_enabled
  subdir('environment')
endif

subdir('tests')
