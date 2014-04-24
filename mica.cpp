#define OS_LINUX
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include  <string>
#include "ICTCLAS50.h"
#include <Python.h>

using namespace std;

static PyObject * mica_translate(PyObject *self, PyObject *args)
{
    PyObject * ret;
    unsigned int nPaLen;
    char * sRst;
    const char * source;

    if (!PyArg_ParseTuple(args, "s", &source))
        return NULL;

    nPaLen = strlen(source);
    sRst = (char *) malloc(nPaLen * 6);
    ICTCLAS_ParagraphProcess(source, nPaLen, sRst, CODE_TYPE_UNKNOWN, 0);
    ret = Py_BuildValue("s", sRst);
    free(sRst);

    return ret;
}

static PyMethodDef MicaMethods[] = {
    {"trans",  mica_translate, METH_VARARGS,
     "Identify chinese character groups."},
    {NULL, NULL, 0, NULL}
};

static PyObject *MicaError;
static string errorname1("mica.error"), errorname2("error");
static char name[100];

PyMODINIT_FUNC
initmica(void)
{
    PyObject *m;

    if(!ICTCLAS_Init()) {
	printf("Init fails\n");  
	PyErr_SetString(MicaError, "MICA ICTCLAS initialization failed!");
	return;
    }

    ICTCLAS_SetPOSmap(2);

    m = Py_InitModule("mica", MicaMethods);

    if (m == NULL)
        return;

    strcpy(name, errorname1.c_str());
    MicaError = PyErr_NewException(name, NULL, NULL);
    Py_INCREF(MicaError);
    strcpy(name, errorname2.c_str());
    PyModule_AddObject(m, name, MicaError);

    //ICTCLAS_Exit();
}

int
main(int argc, char *argv[])
{
    Py_SetProgramName(argv[0]);
    Py_Initialize();
    initmica();
    return 1;
}
