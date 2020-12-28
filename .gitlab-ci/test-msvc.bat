@echo on
:: vcvarsall.bat sets various env vars like PATH, INCLUDE, LIB, LIBPATH for the
:: specified build architecture
call "C:\Program Files (x86)\Microsoft Visual Studio\2017\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64
@echo on

set BUILD_DIR=c:\gnet

:: NOTE: uncomment this in a branch in order to update the depenencies. We do not
:: build it each time to avoid spending so much of time building openssl and glib
:: so we just keep it cached in c:\gnet
::@RD /S /Q %BUILD_DIR%

IF EXIST %BUILD_DIR% GOTO NOGVSBUILD

git clone --depth 1 https://github.com/wingtk/gvsbuild.git -b wip/nacho/glib-2-67 || goto :error

pushd gvsbuild
python.exe build.py --verbose --debug build -p x64 --vs-ver 15 --build-dir %BUILD_DIR% openssl glib || goto :error
popd

:NOGVSBUILD

set DEPS_DIR=%BUILD_DIR%\gtk\x64\release
set PATH=%DEPS_DIR%\bin;%PATH%
set LIB=%DEPS_DIR%\lib;%LIB%
set LIBPATH=%DEPS_DIR%\lib;%LIBPATH%
set INCLUDE=%DEPS_DIR%\include;%DEPS_DIR%\include\glib-2.0;%INCLUDE%
set PKG_CONFIG_PATH=%DEPS_DIR%\lib\pkgconfig

:: FIXME: make warnings fatal
pip3 install --upgrade --user meson==0.53.2  || goto :error
meson build -Dgnutls=disabled -Dopenssl=enabled || goto :error
ninja -C build || goto :error

meson test -C build --timeout-multiplier=10 || goto :error

:: FIXME: can we get code coverage support?

goto :EOF
:error
exit /b 1
