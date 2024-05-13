import setuptools

with open("../README.md") as fp:
    long_description = fp.read()

setuptools.setup(
    name="rds",
    version="1.0.0",

    description="Create a new stack inside of an existing vpc.",
    long_description=long_description,
    long_description_content_type="text/markdown",

    author="Welch, Timothy",

    package_dir={"": "lib"},
    packages=setuptools.find_packages(where="lib"),

    install_requires=[
        "jsii",
        "boto3",
        "aws-cdk-lib",
        "constructs",
        "cdk_ec2_key_pair"
    ],

    python_requires=">=3.6",

    classifiers=[
        "Development Status :: 4 - Beta",

        "Intended Audience :: Developers",

        "License :: OSI Approved :: Apache Software License",

        "Programming Language :: JavaScript",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",

        "Topic :: Software Development :: Code Generators",
        "Topic :: Utilities",

        "Typing :: Typed",
    ],
)
