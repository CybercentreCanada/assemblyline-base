from setuptools import setup, find_packages
import os.path


def read_requirements(path):
    with open(os.path.join(os.path.dirname(__file__), path)) as req:
        lines = req.read().split()

    lines = [line.strip() for line in lines]
    lines = [line.strip() for line in lines if len(line) > 0]
    lines = [line.strip() for line in lines if line[0] != '#']

    return lines


setup(
    name="assemblyline",
    version="0.1",
    packages=find_packages(exclude=['test/*']),
    install_requires=read_requirements('assemblyline/requirements.txt'),
    tests_requires=read_requirements('test/requirements.txt'),
    package_data={
        '': ["*schema.xml", "*managed-schema", "*solrconfig.xml"]
    }
)
