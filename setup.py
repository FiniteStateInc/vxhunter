from distutils.core import setup

setup(name='VxHunter',
      version='1.3.3.7',
      description='Parse the symbol table and find credentials/services for VxWorks.',
      author='Sam Lerner',
      author_email='lerner@finitestate.io',
      url='https://github.com/FiniteStateInc/vxhunter',
      packages=['vxhunter', 'vxhunter.utility'],
     )
