# -*- coding: utf-8 -*-
short_description = 'Python library for interacting with the Amazon MWS API'
try:
    from pypandoc import convert
except (ImportError, OSError):  # either pypandoc or pandoc isn't installed
    long_description = "http://pymazonian.readthedocs.io/en/latest/"
else:
    long_description = convert("README.md", 'rst')

from setuptools import setup

setup(
    name='pymazonian',
    version='0.81',
    maintainer="W. Aaron Morris",
    maintainer_email="waaronmorris@gmail.com",
    url="https://github.com/waaronmorris/pymazonian",
    description=short_description,
    long_description=long_description,
    packages=['pymazonian'],
    install_requires=[
        'requests'
    ],
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development',
        'Topic :: Software Development :: Libraries :: Application Frameworks',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
    ],
    platforms=['OS Independent'],
    license='Unlicense',
    include_package_data=True,
    zip_safe=False
)
