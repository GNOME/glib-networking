tlsbase_headers = files(
  'gtlsconnection-base.h',
  'gtlsinputstream-base.h',
  'gtlsoutputstream-base.h',
)

tlsbase_sources = files(
  'gtlsconnection-base.c',
  'gtlsinputstream-base.c',
  'gtlsoutputstream-base.c',
)

tlsbase = static_library('tlsbase',
                         tlsbase_sources + tlsbase_headers,
                         dependencies: gio_dep,
                         include_directories: top_inc)

tlsbase_dep = declare_dependency(link_with: tlsbase,
                                 include_directories: include_directories('.'),
                                 dependencies: gio_dep)
