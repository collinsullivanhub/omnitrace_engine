import sys
from setuptools import setup, Extension

libraries = []
if sys.platform == 'win32':
    libraries.append('ws2_32')

module = Extension(
    'omnitrace_engine',
    sources=['engine.c'],
    libraries=libraries
)

setup(
    name='omnitrace_engine',
    version='1.0.0',
    description='High-speed raw socket packet traceroute engine',
    ext_modules=[module]
)
