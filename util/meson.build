util_sources = files(
  'ghttp.c'
)

util = static_library('util',
                      util_sources,
                      dependencies: [gio_dep, gmodule_dep],
                      include_directories: top_inc)

util_dep = declare_dependency(link_with: util,
                              include_directories: include_directories('.'),
                              dependencies: gio_dep)
