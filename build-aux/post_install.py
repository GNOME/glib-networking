#!/usr/bin/env python3

import os
import subprocess
import sys

# Packagers handle this
if 'DESTDIR' not in os.environ:
    moduledir = sys.argv[1]
    print('Updating module cache in {}...'.format(moduledir))
    subprocess.check_call(('gio-querymodules', moduledir))
