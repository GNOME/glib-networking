tlsbase_sources = files(
  'gtlsconnection-base.c',
  'gtlsinputstream.c',
  'gtlslog.c',
  'gtlsoutputstream.c',
)

tlsbase = static_library('tlsbase',
                         tlsbase_sources,
                         dependencies: gio_dep,
                         include_directories: top_inc)

tlsbase_dep = declare_dependency(link_with: tlsbase,
                                 include_directories: include_directories('.'),
                                 dependencies: gio_dep)
