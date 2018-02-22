#!/usr/bin/env python
import io

from setuptools import setup


def read(*filenames, **kwargs):
    encoding = kwargs.get('encoding', 'utf-8')
    sep = kwargs.get('sep', '\n')
    buf = []
    for filename in filenames:
        with io.open(filename, encoding=encoding) as f:
            buf.append(f.read())
    return sep.join(buf)


with open('requirements.txt') as reqs:
    install_requires = [
        line for line in reqs.read().split('\n') if (line and not
        line.startswith('--'))
    ]
setup(
    name='aws_kit',
    packages=['aws_kit'],
    version='0.1.0',
    description='A set of aws tools, which can saves clicks on AWS web console.',
    author='Cheney Yan',
    author_email='cheney.yan@gmail.com',
    url='https://github.com/aws-kit/aws-kit',
    download_url='https://github.com/aws-kit/aws-kit',
    keywords=['aws', 'administrator', 'command', 'tools'],
    classifiers=[],
    include_package_data=True,
    entry_points={
        'console_scripts': [
            'vpc-peering = aws_kit.vpc_peering:main',
        ],
    },
    long_description=read('README.rst'),
    install_requires=install_requires,
)
