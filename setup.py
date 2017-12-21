from setuptools import setup, find_packages


setup(
    name='plistutils',

    version='1.0.0',

    description='Convenience functions for plist files',
    long_description=
    """`plistutils` provides a number of convenience functions for dealing with
    Apple Property List files. This module is tested with Python 3.5.""",

    url='https://github.com/strozfriedberg/plistutils',

    # Author details
    author='Stroz Friedberg, an Aon company',
    author_email='gblack@strozfriedberg.com',

    license='BSD 3-clause "New" or "Revised" License',

    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Build Tools',
        'License :: OSI Approved :: BSD 3-clause',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],

    keywords='plist apple mac',

    packages=find_packages(),

    install_requires=['biplist==1.0.3']
)
