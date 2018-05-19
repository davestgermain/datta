from setuptools import setup

import os, sys

os.environ['COPYFILE_DISABLE'] = 'true'  # this disables including resource forks in tar files on os x

extra = {}


setup(
    name="datta",
    use_scm_version=True,
    setup_requires=['setuptools_scm'],
    packages=['datta', 'datta.fs', 'datta.s3_server', 'datta.wiki', 'datta.fs.ext'],
    provides=['datta', 'datta.fs', 'datta.s3_server', 'datta.wiki', 'datta.fs.ext'],
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
