import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="python3-libraccoon", 
    version="1.2.2",
    author="nmmapper",
    author_email="inquiry@nmmapper.com",
    description="libraccon a library for high performance offensive security tool for reconnaissance based on raccoon scanner. This include performing DNS reconnaissance ",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/nmmapper/python3-libraccoon",
    project_urls={
        'Documentation': 'https://github.com/nmmapper/python3-libraccoon',
        'Homepage': 'https://github.com/nmmapper/python3-libraccoon',
        'Source': 'https://github.com/nmmapper/python3-libraccoon',
    },
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
    setup_requires=['wheel'],
    install_requires=['simplejson', "aiodns", "python-whois", "httpx", "beautifulsoup4",
                     "dnspython", "requests", "ipaddress", "xmltodict", "geoip2", "httpx",
                     "aiodns"],
)
