from distutils.core import setup, Extension

module1 = Extension('mica_ictclas',
                    define_macros = [('MAJOR_VERSION', '1'),
                                     ('MINOR_VERSION', '0')],
                    libraries = ['ICTCLAS50'],
                    library_dirs = ['.'],
                    sources = ['mica_ictclas.cpp'])

setup (name = 'PackageName',
       version = '1.0',
       description = 'This is a python-extention for the ICTCLAS package',
       author = 'Michael R. Hines',
       author_email = 'michael@hinespot.com',
       url = 'http://michael.hinespot.com/',
       long_description = '''
       Exposing the C++ ICTCLAS lexical chinese word parser API in Python.
''',
       ext_modules = [module1])
