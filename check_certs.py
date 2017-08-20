#!/usr/bin/env python3

import errno
import os
import sys

for arg in sys.argv[1:]:
  if os.path.isfile(arg):
    sys.stdout.write(arg)
    sys.exit(0)

sys.exit(errno.ENOENT)
