tlsopenssl_sources = [
  'openssl-module.c',
  'gtlsbackend-openssl.c',
  'gtlscertificate-openssl.c',
  'gtlsconnection-openssl.c',
  'gtlsserverconnection-openssl.c',
  'gtlsclientconnection-openssl.c',
  'gtlsdatabase-openssl.c',
  'gtlsfiledatabase-openssl.c',
  'gtlsbio.c',
  'openssl-util.c',
]

platform_deps = [ openssl, gio, glib, gobject ]

tlsopenssl = static_library('tlsopenssl',
                            tlsopenssl_sources,
                            dependencies: [tlsbase_dep, platform_deps],
                            include_directories: config_h_include)

tlsopenssl_dep = declare_dependency(link_with: tlsopenssl,
                                    include_directories: include_directories('.', '../base'),
                                    dependencies: platform_deps)

name_suffix = []

# FIXME: workaround for https://gitlab.gnome.org/GNOME/glib/issues/1413
if host_system == 'darwin'
  name_suffix = 'so'
endif

gioopenssl = shared_module('gioopenssl',
                           tlsopenssl_sources,
                           dependencies: [tlsopenssl_dep],
                           include_directories: config_h_include,
                           name_suffix: name_suffix,
                           install: true,
                           install_dir: gio_module_dir,
                           c_args: [extra_args + common_flags])

# Internal dependency, for tests and benchmarks
tlsopenssl_inc = include_directories([ '.', '..' ])
tlsopenssl_dep = declare_dependency(link_with: tlsopenssl,
                                    include_directories: [ tlsopenssl_inc, config_h_include ],
                                    dependencies: platform_deps)
