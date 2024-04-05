from setuptools import setup, find_packages

VERSION = '0.0.4'

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name='aws_session_handler',
    packages=find_packages(),
    version=VERSION,
    description='AWS Session Handler',
    long_description_content_type='text/markdown',
    long_description=long_description,
    keywords='boto3 amazon web services aws authentication',
    author='MarioVerbelen',
    author_email='mario@verbelen.org',
    url='https://github.com/MarioVerbelen/aws_session_handler',
    download_url='https://github.com/MarioVerbelen/aws_session_handler',
    license='MIT License',
    install_requirements=[
        'botocore',
        'boto3'
    ])
