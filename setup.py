from distutils.core import setup, Extension

module1 = Extension('mica',
                    define_macros = [('MAJOR_VERSION', '1'),
                                     ('MINOR_VERSION', '0')],
                    libraries = ['ICTCLAS50'],
                    library_dirs = ['.'],
                    sources = ['mica.cpp'])

setup (name = 'PackageName',
       version = '1.0',
       description = 'This is a demo package',
       author = 'Michael R. Hines',
       author_email = 'michael@hinespot.com',
       url = 'http://michael.hinespot.com/',
       long_description = '''
       Exposing the C++ Beijing University language word-grouping API program in Python.
''',
       ext_modules = [module1])
