import os

from setuptools import setup, find_packages


def read_requirements(path):
    with open(os.path.join(os.path.dirname(__file__), path)) as req:
        lines = req.read().split()

    lines = [line.strip() for line in lines]
    lines = [line.strip() for line in lines if len(line) > 0]
    lines = [line.strip() for line in lines if line[0] != '#']

    return lines


setup(
    name="assemblyline",
    version="4.0.0.dev2",
    description="Assemblyline (v4) automated malware analysis framework base package.",
    long_description="This package provides the base functionalities for the different Assemblyline v4 components.",
    url="https://bitbucket.org/cse-assemblyline/alv4/",
    author="CCCS Assemblyline development team",
    author_email="assemblyline@cyber.gc.ca",
    licence="MIT",
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
    ],
    keywords="assemblyline malware gc canada cse-cst cse cst cyber cccs",
    packages=find_packages(exclude=['test/*']),
    install_requires=read_requirements('assemblyline/requirements.txt'),
    tests_requires=read_requirements('test/requirements.txt'),
    package_data={
        '': ["*schema.xml", "*managed-schema", "*solrconfig.xml", "*classification.yml", "*.magic"]
    }
)
