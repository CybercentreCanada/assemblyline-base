import os

from setuptools import setup, find_packages, Extension

try:
    from Cython.Build import cythonize
    USE_CYTHON = True
    extension = '.pyx'
except ImportError:
    # If we don't have cython, its fine as long as we are installing from an sdist that already
    # has the pyx files cythonized into c files
    USE_CYTHON = False
    extension = '.c'


# For development and local builds use this version number, but for real builds replace it
# with the tag found in the environment
package_version = "4.0.0.dev0"
if 'BITBUCKET_TAG' in os.environ:
    package_version = os.environ['BITBUCKET_TAG'].lstrip('v')
elif 'BUILD_SOURCEBRANCH' in os.environ:
    full_tag_prefix = 'refs/tags/v'
    package_version = os.environ['BUILD_SOURCEBRANCH'][len(full_tag_prefix):]

# Mark all the modules that need to be compiled here
extensions = [
    Extension('assemblyline.common.frequency', [os.path.join('assemblyline', 'common', 'frequency' + extension)])
]

if USE_CYTHON:
    extensions = cythonize(extensions)

# read the contents of your README file
this_directory = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name="assemblyline",
    version=package_version,
    description="Assemblyline 4 - Automated malware analysis framework",
    long_description=long_description,
    long_description_content_type='text/markdown',
    url="https://github.com/CybercentreCanada/assemblyline-base",
    author="CCCS Assemblyline development team",
    author_email="assemblyline@cyber.gc.ca",
    license="MIT",
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
    ],
    keywords="assemblyline automated malware analysis gc canada cse-cst cse cst cyber cccs",
    packages=find_packages(exclude=['test', 'test/*']),
    ext_modules=extensions,
    install_requires=[
        'arrow',
        'urllib3',
        'python-baseconv',
        'boto3',
        'pysftp',
        'netifaces',
        'pyroute2',
        'redis',
        'requests',
        'elasticsearch>=7.0.0,<8.0.0,!=7.0.3',  # 7.0.3 is excluded due to an error
        'python-datemath',
        'packaging',
        'tabulate',
        'PyYAML',
        'easydict',
        'passlib',
        'cart',
        'ssdeep',
        'python-magic',
        'apscheduler',
        'elastic-apm[flask]',
        'cython',
        'docker',
        'kubernetes',
        'notifications-python-client',
        'azure-storage-blob'
    ],
    extras_require={
        'test': [
            'pytest',
            'pytest-cov',
            'retrying',
        ]
    },
    package_data={
        '': [
            "*classification.yml",
            "*tag_whitelist.yml",
            "*.magic",
            "*sample_rules.yar",
            "*sample_suricata.rules",
            "*.pyx",
            "*.pxd",
        ]
    }
)