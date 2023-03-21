import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="vtpython",
    version="1.2",
    author="Mateo Mrvelj",
    author_email="mateomrvelj99@gmail.com",
    description="A very simple Python package for submitting files to VirusTotal for analysis",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Mateodevv/virustotal-python",
    packages=setuptools.find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
    install_requires=[
        "requests>=2.25.1"
    ],

)
