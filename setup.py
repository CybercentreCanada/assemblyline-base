
from setuptools import setup, find_packages


setup(
    name="assemblyline",
    version="4.0.0.dev8",
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
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
    ],
    keywords="assemblyline malware gc canada cse-cst cse cst cyber cccs",
    packages=find_packages(exclude=['test/*']),
    install_requires=[
        'urllib3<1.25',
        'python-baseconv',
        'boto3',
        'pysftp',
        'netifaces',
        'pyroute2',
        'riak',
        'redis',
        'requests',
        'elasticsearch>=6.0.0,<7.0.0',
        'python-datemath',
        'arrow',
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
    ],
    package_data={
        '': ["*schema.xml", "*managed-schema", "*solrconfig.xml", "*classification.yml", "*.magic"]
    }
)
