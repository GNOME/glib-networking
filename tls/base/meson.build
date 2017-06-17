tlsbase_sources = [
  'gtlsconnection-base.c',
  'gtlsinputstream-base.c',
  'gtlsoutputstream-base.c',
]

tlsbase = static_library('tlsbase',
                         tlsbase_sources,
                         dependencies: gio,
                         include_directories: config_h_include)

tlsbase_dep = declare_dependency(link_with: tlsbase,
                                 include_directories: include_directories('.'),
                                 dependencies: gio)
