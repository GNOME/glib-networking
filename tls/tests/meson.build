incs = [
  top_inc,
  tls_inc
]

deps = [
  gio_dep,
  glib_dep,
  gmodule_dep,
  gobject_dep,
  gnutls_dep
]

cflags = [
  '-DSRCDIR="@0@"'.format(meson.current_source_dir()),
  '-DTOP_BUILDDIR="@0@"'.format(meson.build_root())
]

envs = [
  'G_TEST_SRCDIR=' + meson.current_source_dir(),
  'G_TEST_BUILDDIR=' + meson.current_build_dir(),
]

if enable_installed_tests
  install_subdir('files', install_dir: installed_tests_execdir)
endif

test_programs = [
  ['certificate', [], deps],
  ['file-database', [], deps],
  ['connection', ['mock-interaction.c'], deps],
# DTLS tests are disabled until we fix https://gitlab.gnome.org/GNOME/glib-networking/issues/49
#  ['dtls-connection', ['mock-interaction.c'], deps],
]

foreach backend: backends
  foreach program: test_programs
    # OpenSSL does not support DTLS yet.
    if program[0] == 'dtls-connection' and backend == 'openssl'
      continue
    endif

    program_name = program[0] + '-' + backend

    test_conf = configuration_data()
    test_conf.set('installed_tests_dir', installed_tests_execdir)
    test_conf.set('program', program_name)

    if enable_installed_tests
      configure_file(
        input: test_template,
        output: program_name + '.test',
        install_dir: installed_tests_metadir,
        configuration: test_conf
      )
    endif

    test_cflags = cflags + [
      '-DBACKEND="@0@"'.format(backend),
      '-DBACKEND_IS_' + backend.to_upper(),
    ]

    if backend == 'openssl'
      incs += openssl_inc
    endif

    exe = executable(
      program_name,
      [program[0] + '.c'] + program[1],
      include_directories: incs,
      dependencies: program[2],
      c_args: test_cflags,
      install: enable_installed_tests,
      install_dir: installed_tests_execdir
    )

    test_envs = envs + [
      'GIO_MODULE_DIR=' + join_paths(meson.build_root(), 'tls', backend),
      'G_TEST_SRCDIR=@0@'.format(meson.current_source_dir()),
      'G_TEST_BUILDDIR=@0@'.format(meson.current_build_dir())
    ]

    test(program_name, exe, env: test_envs)

    if backend == 'gnutls' and program[0] == 'connection' or program[0] == 'dtls-connection'
      # Run the tests again, this time with TLS 1.3 disabled so we can test TLS 1.2.
      test(program_name + '-tls1.2', exe, env: test_envs + ['G_TLS_GNUTLS_PRIORITY=NORMAL:%COMPAT:!VERS-TLS1.3'])
    endif
  endforeach
endforeach

if enable_installed_tests
  test_data = files(
    'files/ca-alternative.pem',
    'files/ca-key.pem',
    'files/ca.pem',
    'files/ca-roots-bad.pem',
    'files/ca-roots.pem',
    'files/ca-verisign-sha1.pem',
    'files/chain.pem',
    'files/chain-with-verisign-md2.pem',
    'files/client2-and-key.pem',
    'files/client2-key.pem',
    'files/client2.pem',
    'files/client-and-key.pem',
    'files/client-future.pem',
    'files/client-past.pem',
    'files/client.pem',
    'files/garbage.pem',
    'files/intermediate-ca.pem',
    'files/non-ca.pem',
    'files/server-and-key.pem',
    'files/server.der',
    'files/server-intermediate-key.pem',
    'files/server-intermediate.pem',
    'files/server-key.der',
    'files/server-key.pem',
    'files/server.pem',
    'files/server-self.pem'
  )

  install_data(
    test_data,
    install_dir: join_paths(installed_tests_execdir, 'files')
  )
endif
