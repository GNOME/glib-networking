#!/usr/bin/env python3

import sys
from textwrap import wrap

import gi
gi.require_version('Gcr', '3')
from gi.repository import Gcr

# Read in DER formatted file
with open(sys.argv[1], 'rb') as cert_file:
        cert_bytes = cert_file.read()

cert = Gcr.SimpleCertificate.new(cert_bytes)
issuer_bytes = cert.get_issuer_raw()

print('\\x' + '\\x'.join(wrap(issuer_bytes.hex(), 2)))