unit_tests = [
  [ 'certificate', ['certificate.c'] ],
  [ 'connection', ['connection.c', 'mock-interaction.h', 'mock-interaction.c'] ],
  [ 'file-database', ['file-database.c'] ],
]

test_args = [
  '-DBACKEND="openssl"',
]

foreach unit: unit_tests
  exe = executable(unit[0], unit[1],
                   dependencies: tlsopenssl_dep,
                   include_directories: tlsopenssl_inc,
                   c_args: test_args)
  test(unit[0], exe,
       args: [ '--tap', '-k' ],
       env: [
         'G_TEST_SRCDIR=@0@'.format(meson.current_source_dir()),
         'G_TEST_BUILDDIR=@0@'.format(meson.current_build_dir()),
         'GIO_MODULE_DIR=@0@'.format(join_paths(meson.build_root(), 'tls', 'openssl')),
       ])
endforeach
