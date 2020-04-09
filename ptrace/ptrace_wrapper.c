#include<sys/ptrace.h>
#include<sys/wait.h>
#include<Python.h>

static PyObject*
attach(PyObject *self, PyObject *args)
{
    pid_t pid;

    if (!PyArg_ParseTuple(args, "i", &pid)) {
        goto fail;
    }

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        PyErr_SetFromErrno(PyExc_OSError);
        goto fail;
    };

    waitpid(pid, NULL, 0);

    return Py_None;

fail:
    return NULL;
}

static PyObject*
detach(PyObject *self, PyObject *args)
{
    pid_t pid;

    if (!PyArg_ParseTuple(args, "i", &pid)) {
        goto fail;
    }

    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0) {
        PyErr_SetFromErrno(PyExc_OSError);
        goto fail;
    };

    return Py_None;

fail:
    return NULL;
}

static PyMethodDef PtraceWrapperMethods[] = {
    {"attach", attach, METH_VARARGS, "Args:\n   pid (int): pid of the process to attach to"},
    {"detach", detach, METH_VARARGS, "Args:\n   pid (int): pid of the process to detach from"}
};

static struct PyModuleDef ptrace_wrapper = {
    PyModuleDef_HEAD_INIT,
    "ptrace_wrapper",
    NULL,
    -1,
    PtraceWrapperMethods
};

PyMODINIT_FUNC
PyInit_ptrace_wrapper(void)
{
    return PyModule_Create(&ptrace_wrapper);
}
