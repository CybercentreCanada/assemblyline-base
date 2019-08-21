import os

from setuptools import setup, find_packages

# For development and local builds use this version number, but for real builds replace it
# with the tag found in the environment
package_version = "4.0.0.dev0"
for variable_name in ['BITBUCKET_TAG']:
    package_version = os.environ.get(variable_name, package_version)
    package_version = package_version.lstrip('v')


setup(
    name="assemblyline",
    version=package_version,
    description="Assemblyline (v4) automated malware analysis framework base package.",
    long_description="This package provides the base functionalities for the different Assemblyline v4 components.",
    url="https://bitbucket.org/cse-assemblyline/alv4/",
    author="CCCS Assemblyline development team",
    author_email="assemblyline@cyber.gc.ca",
    license="MIT",
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.7',
    ],
    keywords="assemblyline malware gc canada cse-cst cse cst cyber cccs",
    packages=find_packages(exclude=['test/*']),
    install_requires=[
        'arrow==0.14.4',
        'urllib3<1.25',
        'python-baseconv',
        'boto3',
        'pysftp',
        'netifaces',
        'pyroute2',
        'redis',
        'requests',
        'elasticsearch>=7.0.0,<8.0.0,!=7.0.3',  # Temporarily skip .3 the elasticsearch package until we work out that error
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
    ],
    package_data={
        '': [
            "*schema.xml",
            "*managed-schema",
            "*solrconfig.xml",
            "*classification.yml",
            "*.magic",
            "*sample_rules.yar",
            "*sample_suricata.rules",
            "*.pyx",
            "*.pxd",
        ]
    }
)