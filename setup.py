#!/usr/bin/env python
# Compatibility shim.
#
# All packaging metadata lives in pyproject.toml (PEP 621). This file exists
# only so tooling that still expects a setup.py works — notably the snap build,
# whose `certbot-metadata` part stages setup.py. setuptools reads the real
# configuration from pyproject.toml, so this needs no arguments.
from setuptools import setup

version = '0.0.4'

setup(version=version, name='certbot-dns-noip')
