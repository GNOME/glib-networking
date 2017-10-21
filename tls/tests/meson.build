incs = [top_inc]

deps = [
  gio_dep,
  glib_dep,
  gnutls_dep
]

cflags = [
  '-DSRCDIR="@0@"'.format(meson.current_source_dir()),
  '-DTOP_BUILDDIR="@0@"'.format(meson.build_root())
]

envs = [
  'G_TEST_SRCDIR=' + meson.current_source_dir(),
  'G_TEST_BUILDDIR=' + meson.current_build_dir()
]

test_programs = [
  ['certificate', [], deps],
  ['file-database', [], deps],
  ['connection', ['mock-interaction.c'], deps]
]

if enable_pkcs11_support
  incs += tls_inc

  pkcs11_deps = deps + [
    libgiopkcs11_dep,
    pkcs11_dep
  ]

  test_programs += [
    ['pkcs11-util', [], pkcs11_deps],
    ['pkcs11-array', [], pkcs11_deps],
    ['pkcs11-pin', [], pkcs11_deps],
    ['pkcs11-slot', ['mock-interaction.c', 'mock-pkcs11.c'], pkcs11_deps]
  ]
endif

foreach program: test_programs
  test_conf = configuration_data()
  test_conf.set('installed_tests_dir', installed_tests_execdir)
  test_conf.set('program', program[0])

  configure_file(
    input: test_template,
    output: program[0] + '.test',
    install: enable_installed_tests,
    install_dir: installed_tests_metadir,
    configuration: test_conf
  )

  exe = executable(
    program[0],
    [program[0] + '.c'] + program[1],
    include_directories: incs,
    dependencies: program[2],
    c_args: cflags,
    install: enable_installed_tests,
    install_dir: installed_tests_execdir
  )

  test(
    program[0],
    exe,
    env: envs
  )
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
