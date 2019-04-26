sources = files(
  'gpkcs11array.c',
  'gpkcs11pin.c',
  'gpkcs11slot.c',
  'gpkcs11util.c'
)

deps = [
  glib_dep,
  gio_dep,
  gmodule_dep,
  gobject_dep,
  pkcs11_dep
]

libgiopkcs11 = static_library(
  'giopkcs11',
  sources: sources,
  include_directories: top_inc,
  dependencies: deps,
  install: get_option('static_modules')
)

libgiopkcs11_dep = declare_dependency(
  link_with: libgiopkcs11,
  include_directories: include_directories('.'),
  dependencies: deps
)
