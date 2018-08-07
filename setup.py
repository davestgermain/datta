from setuptools import setup

import os, sys

os.environ['COPYFILE_DISABLE'] = 'true'  # this disables including resource forks in tar files on os x

extra = {}

packages = ['datta', 'datta.fs', 'datta.fs.cas', 'datta.s3_server', 'datta.wiki', 'datta.ext', 'datta.search']
setup(
    name="datta",
    use_scm_version=True,
    setup_requires=['setuptools_scm'],
    packages=packages,
    provides=packages,
    include_package_data=True,
    description='',
    author='Dave St.Germain',
    author_email='dave@st.germa.in',
    license='MIT License',
    install_requires=open('requirements.txt', 'r').readlines(),
    classifiers=[
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 2',
    ],
    **extra
)
