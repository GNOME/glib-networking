cflags = [
  '-DSRCDIR="@0@"'.format(meson.current_source_dir()),
  '-DTOP_BUILDDIR="@0@"'.format(meson.build_root())
]

envs = [
  'G_TEST_SRCDIR=' + meson.current_source_dir(),
  'G_TEST_BUILDDIR=' + meson.current_build_dir()
]

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
    program[0] + '.c',
    include_directories: top_inc,
    dependencies: program[1],
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
