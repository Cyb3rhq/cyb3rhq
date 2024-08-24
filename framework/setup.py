#!/usr/bin/env python

# Copyright (C) 2015, Cyb3rhq Inc.
# Created by Cyb3rhq, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from cyb3rhq import __version__

from setuptools import setup, find_namespace_packages

setup(name='cyb3rhq',
      version=__version__,
      description='Cyb3rhq control with Python',
      url='https://github.com/cyb3rhq',
      author='Cyb3rhq',
      author_email='hello@wazuh.com',
      license='GPLv2',
      packages=find_namespace_packages(exclude=["*.tests", "*.tests.*", "tests.*", "tests"]),
      package_data={'cyb3rhq': ['core/cyb3rhq.json',
                              'core/cluster/cluster.json', 'rbac/default/*.yaml']},
      include_package_data=True,
      install_requires=[],
      zip_safe=False,
      )
