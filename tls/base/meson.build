enums_headers = [
  'gtlsoperationsthread-base.h'
]

enums = gnome.mkenums_simple('tls-base-builtins',
                             sources: enums_headers)

tlsbase_sources = [
  'gtlsconnection-base.c',
  'gtlsinputstream.c',
  'gtlslog.c',
  'gtlsoperationsthread-base.c',
  'gtlsoutputstream.c',
  enums
]

tlsbase = static_library('tlsbase',
                         tlsbase_sources,
                         dependencies: gio_dep,
                         include_directories: top_inc)

tlsbase_dep = declare_dependency(link_with: tlsbase,
                                 include_directories: include_directories('.'),
                                 dependencies: gio_dep)
