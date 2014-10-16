# Copyright (c) 2014 by Farsight Security, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from setuptools import setup, find_packages
from setuptools.extension import Extension
from Cython.Distutils import build_ext

setup(
  name = 'fsisketch',
  author='Henry Stern',
  author_email = 'stern@fsi.io',
  description = 'Disk-Backed Sketch Library',
  long_description = open('README.rst').read(),
  packages = find_packages('src'),
  package_dir = { '' : 'src' },
  cmdclass = { 'build_ext' : build_ext },
  ext_modules=[
      Extension('fsisketch.hash', sources=['src/fsisketch/hash.pyx'])],
  version='0.1',
  url='https://github.com/farsightsec/fsisketch',
  license = 'MIT License',
  test_suite = 'tests',
  requires = [ 'mmaparray', 'mmh3', 'six', 'Cython' ],
  classifiers = [
    'License :: OSI Approved :: Apache Software License',
    'Programming Language :: Cython',
    'Intended Audience :: Developers',
    'Programming Language :: Python :: 2.7',
    'Programming Language :: Python :: 3',
    'Topic :: Software Development :: Libraries',
  ],
)
