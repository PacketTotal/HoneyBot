from distutils.core import setup


def parse_requirements():
    """
    load requirements from a pip requirements file
    """

    lineiter = (line.strip() for line in open('requirements.txt'))
    return [line for line in lineiter if line and not line.startswith("#")]


install_reqs = parse_requirements()

setup(
    name='honeybot',
    version='0.5.0',
    packages=['honeybot.lib', 'packettotal_sdk'],
    scripts=['bin/capture-and-analyze.py', 'bin/trigger-and-analyze.py', 'bin/upload-and-analyze.py'],
    url='https://packettotal.com',
    license='MIT',
    author='Jamin Becker',
    author_email='jamin@packettotal.com',
    description='A suite of utilities providing the ability to do bulk network analysis with PacketTotal.com',
    install_reqires=install_reqs
)
