#!/usr/bin/env python

# Copyright (C) 2015, Cyb3rhq Inc.
# Created by Cyb3rhq, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from setuptools import setup, find_namespace_packages

# To install the library, run the following
#
# python setup.py install
#
# prerequisite: setuptools
# http://pypi.python.org/pypi/setuptools

setup(
    name='api',
    version='5.0.0',
    description="Cyb3rhq API",
    author_email="hello@wazuh.com",
    author="Cyb3rhq",
    url="https://github.com/cyb3rhq",
    keywords=["Cyb3rhq API"],
    install_requires=[],
    packages=find_namespace_packages(exclude=["*.test", "*.test.*", "test.*", "test"]),
    package_data={'': ['spec/spec.yaml']},
    include_package_data=True,
    zip_safe=False,
    license='GPLv2',
    long_description="""\
    The Cyb3rhq API is an open source RESTful API that allows for interaction with the Cyb3rhq manager from a web browser, command line tool like cURL or any script or program that can make web requests. The Cyb3rhq app relies on this heavily and Cyb3rhq’s goal is to accommodate complete remote management of the Cyb3rhq infrastructure via the Cyb3rhq app. Use the API to easily perform everyday actions like adding an agent, restarting the manager(s) or agent(s) or looking up syscheck details.
    """
)
