#include <Python.h>

#include "py_plugin_host.h"
#include "basic_ciphers.h"
#include "historical_ciphers.h"
#include "standard_ciphers.h"
#include "essential_ciphers.h"
#include "modern_ciphers.h"
#include "detector.h"
#include "bytes.h"

#include <cstring>
#include <iostream>
#include <memory>

// ═══════════════════════════════════════════════════════════════════════════
// Python C extension: module "obscuron"
// ═══════════════════════════════════════════════════════════════════════════

static PyObject* py_caesar(PyObject*, PyObject *args) {
    const char *text; int shift;
    if (!PyArg_ParseTuple(args, "si", &text, &shift)) return NULL;
    try {
        std::string in(text), out;
        ::custom_rot(in, shift, out);
        return PyUnicode_FromString(out.c_str());
    } catch (const std::exception &e) {
        PyErr_SetString(PyExc_RuntimeError, e.what()); return NULL;
    }
}

static PyObject* py_rot13(PyObject*, PyObject *args) {
    const char *text;
    if (!PyArg_ParseTuple(args, "s", &text)) return NULL;
    try {
        std::string in(text), out;
        ::rot13(in, out);
        return PyUnicode_FromString(out.c_str());
    } catch (const std::exception &e) {
        PyErr_SetString(PyExc_RuntimeError, e.what()); return NULL;
    }
}

static PyObject* py_rot47(PyObject*, PyObject *args) {
    const char *text;
    if (!PyArg_ParseTuple(args, "s", &text)) return NULL;
    try {
        std::string in(text), out;
        ::rot47(in, out);
        return PyUnicode_FromString(out.c_str());
    } catch (const std::exception &e) {
        PyErr_SetString(PyExc_RuntimeError, e.what()); return NULL;
    }
}

static PyObject* py_atbash(PyObject*, PyObject *args) {
    const char *text;
    if (!PyArg_ParseTuple(args, "s", &text)) return NULL;
    try {
        std::string in(text), out;
        ::atbash(in, out);
        return PyUnicode_FromString(out.c_str());
    } catch (const std::exception &e) {
        PyErr_SetString(PyExc_RuntimeError, e.what()); return NULL;
    }
}

static PyObject* py_vigenere(PyObject*, PyObject *args) {
    const char *text, *key; int decrypt = 0;
    if (!PyArg_ParseTuple(args, "ss|p", &text, &key, &decrypt)) return NULL;
    try {
        std::string in(text), out;
        ::vigenere(in, key, out, !decrypt);
        return PyUnicode_FromString(out.c_str());
    } catch (const std::exception &e) {
        PyErr_SetString(PyExc_RuntimeError, e.what()); return NULL;
    }
}

static PyObject* py_railfence(PyObject*, PyObject *args) {
    const char *text; int rails, offset = 0;
    if (!PyArg_ParseTuple(args, "si|i", &text, &rails, &offset)) return NULL;
    try {
        std::string in(text), out;
        ::railfence(in, out, rails, offset);
        return PyUnicode_FromString(out.c_str());
    } catch (const std::exception &e) {
        PyErr_SetString(PyExc_RuntimeError, e.what()); return NULL;
    }
}

static PyObject* py_columnar_encrypt(PyObject*, PyObject *args) {
    const char *text, *key;
    if (!PyArg_ParseTuple(args, "ss", &text, &key)) return NULL;
    try {
        std::string in(text), out;
        ::columnar_encrypt(in, out, key);
        return PyUnicode_FromString(out.c_str());
    } catch (const std::exception &e) {
        PyErr_SetString(PyExc_RuntimeError, e.what()); return NULL;
    }
}

static PyObject* py_columnar_decrypt(PyObject*, PyObject *args) {
    const char *text, *key; int origLen;
    if (!PyArg_ParseTuple(args, "ssi", &text, &key, &origLen)) return NULL;
    try {
        std::string in(text), out;
        ::columnar_decrypt(in, out, key, origLen);
        return PyUnicode_FromString(out.c_str());
    } catch (const std::exception &e) {
        PyErr_SetString(PyExc_RuntimeError, e.what()); return NULL;
    }
}

static PyObject* py_beaufort(PyObject*, PyObject *args) {
    const char *text, *key;
    if (!PyArg_ParseTuple(args, "ss", &text, &key)) return NULL;
    try {
        std::string in(text), out;
        ::beaufort(in, key, out);
        return PyUnicode_FromString(out.c_str());
    } catch (const std::exception &e) {
        PyErr_SetString(PyExc_RuntimeError, e.what()); return NULL;
    }
}

static PyObject* py_xor_single(PyObject*, PyObject *args) {
    const char *text; int keyByte;
    if (!PyArg_ParseTuple(args, "si", &text, &keyByte)) return NULL;
    try {
        std::string in(text), out;
        ::hex_xor(in, static_cast<unsigned char>(keyByte & 0xFF), out);
        return PyUnicode_FromString(out.c_str());
    } catch (const std::exception &e) {
        PyErr_SetString(PyExc_RuntimeError, e.what()); return NULL;
    }
}

static PyObject* py_xor_string(PyObject*, PyObject *args) {
    const char *text, *key;
    if (!PyArg_ParseTuple(args, "ss", &text, &key)) return NULL;
    try {
        std::string in(text), out;
        ::str_xor(in, key, out);
        return PyUnicode_FromString(out.c_str());
    } catch (const std::exception &e) {
        PyErr_SetString(PyExc_RuntimeError, e.what()); return NULL;
    }
}

static PyObject* py_bacon(PyObject*, PyObject *args) {
    const char *text; int decrypt = 0;
    if (!PyArg_ParseTuple(args, "s|p", &text, &decrypt)) return NULL;
    try {
        std::string in(text), out;
        ::bacon(in, out, decrypt != 0);
        return PyUnicode_FromString(out.c_str());
    } catch (const std::exception &e) {
        PyErr_SetString(PyExc_RuntimeError, e.what()); return NULL;
    }
}

static PyObject* py_morse_encode(PyObject*, PyObject *args) {
    const char *text;
    if (!PyArg_ParseTuple(args, "s", &text)) return NULL;
    try {
        std::string in(text), out;
        ::morse_encode(in, out);
        return PyUnicode_FromString(out.c_str());
    } catch (const std::exception &e) {
        PyErr_SetString(PyExc_RuntimeError, e.what()); return NULL;
    }
}

static PyObject* py_morse_decode(PyObject*, PyObject *args) {
    const char *text;
    if (!PyArg_ParseTuple(args, "s", &text)) return NULL;
    try {
        std::string in(text), out;
        ::morse_decode(in, out);
        return PyUnicode_FromString(out.c_str());
    } catch (const std::exception &e) {
        PyErr_SetString(PyExc_RuntimeError, e.what()); return NULL;
    }
}

static PyObject* py_hex_encode(PyObject*, PyObject *args) {
    const char *text;
    if (!PyArg_ParseTuple(args, "s", &text)) return NULL;
    try {
        std::string in(text), out;
        const std::string hexalpha = "0123456789ABCDEF";
        ::proper_base_convert(in, out, 4, hexalpha);
        return PyUnicode_FromString(out.c_str());
    } catch (const std::exception &e) {
        PyErr_SetString(PyExc_RuntimeError, e.what()); return NULL;
    }
}

static PyObject* py_hex_decode(PyObject*, PyObject *args) {
    const char *text;
    if (!PyArg_ParseTuple(args, "s", &text)) return NULL;
    try {
        return PyUnicode_FromString(::from_hex(text).c_str());
    } catch (const std::exception &e) {
        PyErr_SetString(PyExc_RuntimeError, e.what()); return NULL;
    }
}

static PyObject* py_base64_encode(PyObject*, PyObject *args) {
    const char *text;
    if (!PyArg_ParseTuple(args, "s", &text)) return NULL;
    try {
        return PyUnicode_FromString(::base64_encode(text).c_str());
    } catch (const std::exception &e) {
        PyErr_SetString(PyExc_RuntimeError, e.what()); return NULL;
    }
}

static PyObject* py_base64_decode(PyObject*, PyObject *args) {
    const char *text;
    if (!PyArg_ParseTuple(args, "s", &text)) return NULL;
    try {
        return PyUnicode_FromString(::base64_decode(text).c_str());
    } catch (const std::exception &e) {
        PyErr_SetString(PyExc_RuntimeError, e.what()); return NULL;
    }
}

static PyObject* py_md5(PyObject*, PyObject *args) {
    const char *text;
    if (!PyArg_ParseTuple(args, "s", &text)) return NULL;
    try {
        std::string in(text), out;
        ::md5_hash(in, out);
        return PyUnicode_FromString(out.c_str());
    } catch (const std::exception &e) {
        PyErr_SetString(PyExc_RuntimeError, e.what()); return NULL;
    }
}

static PyObject* py_sha256(PyObject*, PyObject *args) {
    const char *text;
    if (!PyArg_ParseTuple(args, "s", &text)) return NULL;
    try {
        std::string in(text), out;
        ::sha256_hash(in, out);
        return PyUnicode_FromString(out.c_str());
    } catch (const std::exception &e) {
        PyErr_SetString(PyExc_RuntimeError, e.what()); return NULL;
    }
}

static PyObject* py_entropy(PyObject*, PyObject *args) {
    const char *text;
    if (!PyArg_ParseTuple(args, "s", &text)) return NULL;
    try {
        return PyFloat_FromDouble(::compute_entropy(text));
    } catch (const std::exception &e) {
        PyErr_SetString(PyExc_RuntimeError, e.what()); return NULL;
    }
}

static PyMethodDef ObscuronMethods[] = {
    {"caesar",          py_caesar,          METH_VARARGS, NULL},
    {"rot13",           py_rot13,           METH_VARARGS, NULL},
    {"rot47",           py_rot47,           METH_VARARGS, NULL},
    {"atbash",          py_atbash,          METH_VARARGS, NULL},
    {"vigenere",        py_vigenere,        METH_VARARGS, NULL},
    {"railfence",       py_railfence,       METH_VARARGS, NULL},
    {"columnar_encrypt",py_columnar_encrypt,METH_VARARGS, NULL},
    {"columnar_decrypt",py_columnar_decrypt,METH_VARARGS, NULL},
    {"beaufort",        py_beaufort,        METH_VARARGS, NULL},
    {"xor_single",      py_xor_single,      METH_VARARGS, NULL},
    {"xor_string",      py_xor_string,      METH_VARARGS, NULL},
    {"bacon",           py_bacon,           METH_VARARGS, NULL},
    {"morse_encode",    py_morse_encode,    METH_VARARGS, NULL},
    {"morse_decode",    py_morse_decode,    METH_VARARGS, NULL},
    {"hex_encode",      py_hex_encode,      METH_VARARGS, NULL},
    {"hex_decode",      py_hex_decode,      METH_VARARGS, NULL},
    {"base64_encode",   py_base64_encode,   METH_VARARGS, NULL},
    {"base64_decode",   py_base64_decode,   METH_VARARGS, NULL},
    {"md5",             py_md5,             METH_VARARGS, NULL},
    {"sha256",          py_sha256,          METH_VARARGS, NULL},
    {"entropy",         py_entropy,         METH_VARARGS, NULL},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef obscuron_module = {
    PyModuleDef_HEAD_INIT,
    "obscuron",
    NULL,
    -1,
    ObscuronMethods,
    NULL, NULL, NULL, NULL
};

extern "C" PyMODINIT_FUNC PyInit_obscuron(void) {
    return PyModule_Create(&obscuron_module);
}

// ═══════════════════════════════════════════════════════════════════════════
// PyPluginHost implementation
// ═══════════════════════════════════════════════════════════════════════════

PyPluginHost& PyPluginHost::instance() {
    static PyPluginHost host;
    return host;
}

bool PyPluginHost::initialize() {
    auto &inst = instance();
    if (inst.m_initialized) return true;

    PyImport_AppendInittab("obscuron", PyInit_obscuron);
    Py_Initialize();

    inst.m_bridgeModule = PyImport_ImportModule("obscuron");
    if (!inst.m_bridgeModule) {
        PyErr_Clear();
        std::cerr << "PyPluginHost: Failed to create obscuron module" << std::endl;
        Py_Finalize();
        return false;
    }

    inst.m_initialized = true;
    return true;
}

void PyPluginHost::finalize() {
    auto &inst = instance();
    if (!inst.m_initialized) return;
    inst.m_initialized = false;
    Py_XDECREF(inst.m_bridgeModule);
    inst.m_bridgeModule = nullptr;
    if (Py_IsInitialized())
        Py_Finalize();
}

PyObject* PyPluginHost::loadScript(const std::string &path, std::string &error) {
    if (!m_initialized) {
        error = "Python interpreter not initialized";
        return nullptr;
    }

    std::string dir = path.substr(0, path.find_last_of('/'));
    std::string filename = path.substr(path.find_last_of('/') + 1);
    std::string modName = filename;
    size_t dot = modName.rfind('.');
    if (dot != std::string::npos) modName = modName.substr(0, dot);

    PyObject *dirObj = PyUnicode_FromString(dir.c_str());
    PyObject *sysPath = PySys_GetObject("path");
    PyList_Insert(sysPath, 0, dirObj);
    Py_DECREF(dirObj);

    PyObject *modNameObj = PyUnicode_FromString(modName.c_str());
    PyObject *module = PyImport_Import(modNameObj);
    Py_DECREF(modNameObj);

    PyList_SetSlice(sysPath, 0, 1, NULL);

    if (!module) {
        PyObject *exc = PyErr_GetRaisedException();
        if (exc) {
            PyObject *str = PyObject_Str(exc);
            if (str) {
                error = PyUnicode_AsUTF8(str);
                Py_DECREF(str);
            }
            Py_DECREF(exc);
        } else {
            error = "Unknown import error for " + path;
        }
        return nullptr;
    }

    return module;
}

std::string PyPluginHost::execute(PyObject *module, const std::string &funcName,
                                   const std::string &input, const std::string &key,
                                   const std::string &iv,
                                   int param1, int param2, int encrypt,
                                   bool &success, std::string &error)
{
    success = false;
    if (!module) { error = "Null module"; return {}; }

    PyObject *func = PyObject_GetAttrString(module, funcName.c_str());
    if (!func || !PyCallable_Check(func)) {
        Py_XDECREF(func);
        error = "Function '" + funcName + "' not found in plugin";
        return {};
    }

    PyObject *result = PyObject_CallFunction(func, "sssiii",
        input.c_str(), key.c_str(), iv.c_str(),
        param1, param2, encrypt);
    Py_DECREF(func);

    if (!result) {
        PyObject *exc = PyErr_GetRaisedException();
        if (exc) {
            PyObject *str = PyObject_Str(exc);
            if (str) {
                error = PyUnicode_AsUTF8(str);
                Py_DECREF(str);
            }
            Py_DECREF(exc);
        } else {
            error = "Python function returned NULL";
        }
        return {};
    }

    std::string out;
    PyObject *resultStr = PyObject_Str(result);
    if (resultStr) {
        out = PyUnicode_AsUTF8(resultStr);
        Py_DECREF(resultStr);
    }
    Py_DECREF(result);
    success = true;
    return out;
}
