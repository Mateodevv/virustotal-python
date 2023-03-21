import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="vtpython",
    version="2.6",
    author="Mateo Mrvelj",
    author_email="burningmalwareblog@gmail.com",
    description="A very simple Python package for submitting files to VirusTotal for analysis",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Mateodevv/virustotal-python",
    packages=['vtpython'],
    py_modules=['vtpython'],
    python_requires='>=3.6',
    install_requires=[
        "requests>=2.25.1"
    ],
    license='MIT',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
    ],

)
