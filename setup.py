import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="xfrserver",
    version="0.1",
    author="PowerDNS",
    author_email="peter.van.dijk@powerdns.com",
    description="xfrserver used in PowerDNS testing",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/PowerDNS/xfrserver",
    packages=setuptools.find_packages(),
    install_requires=[
        "dnspython"
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
        "Operating System :: OS Independent",
    ],
)