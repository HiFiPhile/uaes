from setuptools import setup, Extension
import os

# Read the long description from README.md
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

uaes_module = Extension(
    'uaes',
    sources=['uaes.c', 'crypt_lib.c'],
    include_dirs=['.'],
)

setup(
    name='uaes',
    version='0.1.0',
    author='Zixun LI',
    author_email='admin@hifiphile.com',
    description='Lightweight, zero-dependency Micro AES CPython extension',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/HiFiPhile/uaes',
    ext_modules=[uaes_module],
    # PEP 561 stub package for top-level module
    packages=['uaes-stubs'],
    package_data={'uaes-stubs': ['__init__.pyi']},
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Topic :: Security :: Cryptography',
        'Topic :: Software Development :: Embedded Systems',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: C',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.7',
)
