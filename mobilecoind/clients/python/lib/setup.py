import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="mobilecoin",
    version="0.2.0",
    author="MobileCoin",
    author_email="support@mobilecoin.com",
    description="Python bindings for the MobileCoin daemon API.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/mobilecoinofficial/mobilecoin/tree/master/mobilecoind/clients/python/lib",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)
