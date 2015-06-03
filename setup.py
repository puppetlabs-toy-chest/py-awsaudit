from setuptools import setup, find_packages

setup(
    name='awsaudit',
    version='0.1.0',
    packages=find_packages(),
    install_requires=[
        'boto',
        'pytz',
        'requests',
        'sendgrid'],
    author='Puppet Labs Operations',
    author_email='sysops-dept@puppetlabs.com',
    description="Puppet Labs' simple AWS EC2 auditing tool",
    license='Apache License 2.0',
    url='https://github.com/puppetlabs/py-awsaudit',
    entry_points={
        'console_scripts': [
            'awsaudit = awsaudit.cli:main',
            'awsreport = awsaudit.report:main'
        ]
    }
)
