import os

from setuptools import Extension, find_packages, setup

# Try to load the version from a datafile in the package
package_version = "4.0.0.dev0"
package_version_path = os.path.join(os.path.dirname(__file__), 'assemblyline', 'VERSION')
if os.path.exists(package_version_path):
    with open(package_version_path) as package_version_file:
        package_version = package_version_file.read().strip()


# Mark all the modules that need to be compiled here
extensions = [
    Extension('assemblyline.common.frequency', [os.path.join('assemblyline', 'common', 'frequency.pyx')])
]

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
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
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
        'python-datemath!=3.0.2',
        'packaging',
        'tabulate',
        'PyYAML',
        'easydict',
        'bcrypt',
        'cart',
        'ssdeep',
        'python-magic',
        'pytz',
        'apscheduler',
        'websocket_client<1.0.0',
        'elastic-apm[flask]>=6.13.0',
        'cython',
        'docker',
        'kubernetes>18',
        'notifications-python-client',
        'rstr',
        # Blacklist a bad release of the azure library until a release newer than that comes out
        'azure-storage-blob!=12.4.0',
        'azure-identity',
        'msoffcrypto-tool',
        'chardet',
        'yara-python',
        'python-tlsh',
        'hauntedhouse==0.1.10',
        'magika',
    ],
    extras_require={
        'test': [
            'pytest',
            'retrying',
            'pytest-mock',
            'pyftpdlib',
            'pyopenssl==23.3.0',
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
        ],
        "assemblyline": ["py.typed"]
    },
    entry_points= {
        "console_scripts": ["al_cli=assemblyline.run.cli:shell_main"]
    }
)
