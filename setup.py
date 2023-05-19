import os

from setuptools import setup, find_packages, Extension

try:
    # noinspection PyUnresolvedReferences,PyPackageRequirements
    from Cython.Build import cythonize
    USE_CYTHON = True
    extension = '.pyx'
except ImportError:
    # If we don't have cython, its fine as long as we are installing from an sdist that already
    # has the pyx files cythonized into c files
    USE_CYTHON = False
    extension = '.c'

# Try to load the version from a datafile in the package
package_version = "4.0.0.dev0"
package_version_path = os.path.join(os.path.dirname(__file__), 'assemblyline', 'VERSION')
if os.path.exists(package_version_path):
    with open(package_version_path) as package_version_file:
        package_version = package_version_file.read().strip()


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
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
    ],
    keywords="assemblyline automated malware analysis gc canada cse-cst cse cst cyber cccs",
    packages=find_packages(exclude=['test', 'test/*']),
    ext_modules=extensions,
    install_requires=[
        'arrow',
        'aiohttp',
        'lark',
        'urllib3',
        'python-baseconv',
        'boto3',
        'pysftp',
        'netifaces',
        'pyroute2.core',
        'redis',
        'requests[socks]',
        'elasticsearch>=8.0.0,<9.0.0',
        'python-datemath',
        'packaging',
        'tabulate',
        'PyYAML',
        'easydict',
        'passlib',
        'cart',
        'ssdeep',
        'python-magic',
        'pytz',
        'apscheduler',
        'websocket_client<1.0.0',
        'elastic-apm[flask]!=6.3.0,!=6.3.1,!=6.3.2,<6.13.0',  # Exclude broken elastic APM version
        'cython',
        'docker',
        'kubernetes>18',
        'notifications-python-client',
        # Blacklist a bad release of the azure library until a release newer than that comes out
        'azure-storage-blob!=12.4.0',
        'azure-identity',
        'msoffcrypto-tool',
        'chardet',
        'yara-python',
        'python-tlsh'
    ],
    extras_require={
        'test': [
            'pytest',
            'retrying',
            'pytest-mock',
            'pyftpdlib',
            'pyopenssl',
        ]
    },
    package_data={
        '': [
            "*classification.yml",
            "*tag_safelist.yml",
            "*.magic",
            "*.yara",
            "*sample_rules.yar",
            "*sample_suricata.rules",
            "*.pyx",
            "*.pxd",
            "*.lark",
            "VERSION",
        ]
    }
)
