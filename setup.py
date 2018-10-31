from distutils.core import setup

def parse_requirements(filename):
    """
    load requirements from a pip requirements file
    """

    lineiter = (line.strip() for line in open('requirements.txt'))
    return [line for line in lineiter if line and not line.startswith("#")]

install_reqs = parse_requirements("requirements.txt")
setup(
    name='SnappyCap',
    version='0.5.0',
    packages=['snappycap.lib'],
    scripts=['bin/capture-and-analyze.py', 'bin/upload-and-analyze.py'],
    url='https://packettotal.com',
    license='MIT',
    author='Jamin Becker',
    author_email='jamin@packettotal.com',
    description='Capture, upload and analyze network traffic; powered by PacketTotal.com.',
    install_reqires=install_reqs
)
