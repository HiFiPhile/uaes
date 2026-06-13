#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "crypt_lib.h"

static int get_mode_from_keylen(Py_ssize_t key_len, AES_Mode_t *mode) {
    if (key_len == 16) { *mode = AES_Mode_128; return 1; }
    if (key_len == 24) { *mode = AES_Mode_192; return 1; }
    if (key_len == 32) { *mode = AES_Mode_256; return 1; }
    PyErr_SetString(PyExc_ValueError, "Key must be 16, 24, or 32 bytes long");
    return 0;
}

// -----------------------------------------------------------------------------
// AES_ECB
// -----------------------------------------------------------------------------
typedef struct {
    PyObject_HEAD
    AES_Ctx_t ctx;
} AES_ECBObject;

static int AES_ECB_init(AES_ECBObject *self, PyObject *args, PyObject *kwds) {
    const char *key;
    Py_ssize_t key_len;
    AES_Mode_t mode;
    static char *kwlist[] = {"key", NULL};
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "y#", kwlist, &key, &key_len)) return -1;
    if (!get_mode_from_keylen(key_len, &mode)) return -1;
    AES_Init_Ctx(&self->ctx, (const uint8_t*)key, mode);
    return 0;
}

static PyObject* AES_ECB_encrypt(AES_ECBObject *self, PyObject *args) {
    const char *data;
    Py_ssize_t data_len;
    if (!PyArg_ParseTuple(args, "y#", &data, &data_len)) return NULL;
    if (data_len % 16 != 0) {
        PyErr_SetString(PyExc_ValueError, "Data length must be a multiple of 16 bytes");
        return NULL;
    }
    PyObject *out = PyBytes_FromStringAndSize(data, data_len);
    if (!out) return NULL;
    AES_ECB_Encrypt(&self->ctx, (uint8_t*)PyBytes_AS_STRING(out), (uint32_t)data_len);
    return out;
}

static PyObject* AES_ECB_decrypt(AES_ECBObject *self, PyObject *args) {
    const char *data;
    Py_ssize_t data_len;
    if (!PyArg_ParseTuple(args, "y#", &data, &data_len)) return NULL;
    if (data_len % 16 != 0) {
        PyErr_SetString(PyExc_ValueError, "Data length must be a multiple of 16 bytes");
        return NULL;
    }
    PyObject *out = PyBytes_FromStringAndSize(data, data_len);
    if (!out) return NULL;
    AES_ECB_Decrypt(&self->ctx, (uint8_t*)PyBytes_AS_STRING(out), (uint32_t)data_len);
    return out;
}

static PyObject* AES_ECB_encrypt_into(AES_ECBObject *self, PyObject *args) {
    Py_buffer buf;
    if (!PyArg_ParseTuple(args, "w*", &buf)) return NULL;
    if (buf.len % 16 != 0) {
        PyBuffer_Release(&buf);
        PyErr_SetString(PyExc_ValueError, "Data length must be a multiple of 16 bytes");
        return NULL;
    }
    AES_ECB_Encrypt(&self->ctx, (uint8_t*)buf.buf, (uint32_t)buf.len);
    PyBuffer_Release(&buf);
    Py_RETURN_NONE;
}

static PyObject* AES_ECB_decrypt_into(AES_ECBObject *self, PyObject *args) {
    Py_buffer buf;
    if (!PyArg_ParseTuple(args, "w*", &buf)) return NULL;
    if (buf.len % 16 != 0) {
        PyBuffer_Release(&buf);
        PyErr_SetString(PyExc_ValueError, "Data length must be a multiple of 16 bytes");
        return NULL;
    }
    AES_ECB_Decrypt(&self->ctx, (uint8_t*)buf.buf, (uint32_t)buf.len);
    PyBuffer_Release(&buf);
    Py_RETURN_NONE;
}

static PyMethodDef AES_ECB_methods[] = {
    {"encrypt", (PyCFunction)AES_ECB_encrypt, METH_VARARGS, "Encrypt data in ECB mode (returns new bytes)"},
    {"decrypt", (PyCFunction)AES_ECB_decrypt, METH_VARARGS, "Decrypt data in ECB mode (returns new bytes)"},
    {"encrypt_into", (PyCFunction)AES_ECB_encrypt_into, METH_VARARGS, "Encrypt writable buffer in-place"},
    {"decrypt_into", (PyCFunction)AES_ECB_decrypt_into, METH_VARARGS, "Decrypt writable buffer in-place"},
    {NULL}
};

static PyTypeObject AES_ECBType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "uaes.AES_ECB",
    .tp_doc = "AES ECB context",
    .tp_basicsize = sizeof(AES_ECBObject),
    .tp_itemsize = 0,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_new = PyType_GenericNew,
    .tp_init = (initproc)AES_ECB_init,
    .tp_methods = AES_ECB_methods,
};

// -----------------------------------------------------------------------------
// AES_CBC
// -----------------------------------------------------------------------------
typedef struct {
    PyObject_HEAD
    AES_Ctx_t ctx;
} AES_CBCObject;

static int AES_CBC_init(AES_CBCObject *self, PyObject *args, PyObject *kwds) {
    const char *key, *iv = NULL;
    Py_ssize_t key_len, iv_len = 0;
    AES_Mode_t mode;
    static char *kwlist[] = {"key", "iv", NULL};
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "y#|y#", kwlist, &key, &key_len, &iv, &iv_len)) return -1;
    if (!get_mode_from_keylen(key_len, &mode)) return -1;
    uint8_t iv_bytes[16] = {0};
    if (iv) {
        if (iv_len != 16) { PyErr_SetString(PyExc_ValueError, "IV must be 16 bytes"); return -1; }
        memcpy(iv_bytes, iv, 16);
    }
    AES_Init_Ctx_Iv(&self->ctx, (const uint8_t*)key, iv_bytes, mode);
    return 0;
}

static PyObject* AES_CBC_set_iv(AES_CBCObject *self, PyObject *args) {
    const char *iv;
    Py_ssize_t iv_len;
    if (!PyArg_ParseTuple(args, "y#", &iv, &iv_len)) return NULL;
    if (iv_len != 16) { PyErr_SetString(PyExc_ValueError, "IV must be 16 bytes"); return NULL; }
    AES_Ctx_Set_Iv(&self->ctx, (const uint8_t*)iv);
    Py_RETURN_NONE;
}

static PyObject* AES_CBC_encrypt(AES_CBCObject *self, PyObject *args) {
    const char *data;
    Py_ssize_t data_len;
    if (!PyArg_ParseTuple(args, "y#", &data, &data_len)) return NULL;
    if (data_len % 16 != 0) {
        PyErr_SetString(PyExc_ValueError, "Data length must be a multiple of 16 bytes");
        return NULL;
    }
    PyObject *out = PyBytes_FromStringAndSize(data, data_len);
    if (!out) return NULL;
    AES_CBC_Encrypt(&self->ctx, (uint8_t*)PyBytes_AS_STRING(out), (uint32_t)data_len);
    return out;
}

static PyObject* AES_CBC_decrypt(AES_CBCObject *self, PyObject *args) {
    const char *data;
    Py_ssize_t data_len;
    if (!PyArg_ParseTuple(args, "y#", &data, &data_len)) return NULL;
    if (data_len % 16 != 0) {
        PyErr_SetString(PyExc_ValueError, "Data length must be a multiple of 16 bytes");
        return NULL;
    }
    PyObject *out = PyBytes_FromStringAndSize(data, data_len);
    if (!out) return NULL;
    AES_CBC_Decrypt(&self->ctx, (uint8_t*)PyBytes_AS_STRING(out), (uint32_t)data_len);
    return out;
}

static PyObject* AES_CBC_encrypt_into(AES_CBCObject *self, PyObject *args) {
    Py_buffer buf;
    if (!PyArg_ParseTuple(args, "w*", &buf)) return NULL;
    if (buf.len % 16 != 0) {
        PyBuffer_Release(&buf);
        PyErr_SetString(PyExc_ValueError, "Data length must be a multiple of 16 bytes");
        return NULL;
    }
    AES_CBC_Encrypt(&self->ctx, (uint8_t*)buf.buf, (uint32_t)buf.len);
    PyBuffer_Release(&buf);
    Py_RETURN_NONE;
}

static PyObject* AES_CBC_decrypt_into(AES_CBCObject *self, PyObject *args) {
    Py_buffer buf;
    if (!PyArg_ParseTuple(args, "w*", &buf)) return NULL;
    if (buf.len % 16 != 0) {
        PyBuffer_Release(&buf);
        PyErr_SetString(PyExc_ValueError, "Data length must be a multiple of 16 bytes");
        return NULL;
    }
    AES_CBC_Decrypt(&self->ctx, (uint8_t*)buf.buf, (uint32_t)buf.len);
    PyBuffer_Release(&buf);
    Py_RETURN_NONE;
}

static PyMethodDef AES_CBC_methods[] = {
    {"encrypt", (PyCFunction)AES_CBC_encrypt, METH_VARARGS, "Encrypt data in CBC mode (returns new bytes)"},
    {"decrypt", (PyCFunction)AES_CBC_decrypt, METH_VARARGS, "Decrypt data in CBC mode (returns new bytes)"},
    {"encrypt_into", (PyCFunction)AES_CBC_encrypt_into, METH_VARARGS, "Encrypt writable buffer in-place"},
    {"decrypt_into", (PyCFunction)AES_CBC_decrypt_into, METH_VARARGS, "Decrypt writable buffer in-place"},
    {"set_iv", (PyCFunction)AES_CBC_set_iv, METH_VARARGS, "Set IV"},
    {NULL}
};

static PyTypeObject AES_CBCType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "uaes.AES_CBC",
    .tp_doc = "AES CBC context",
    .tp_basicsize = sizeof(AES_CBCObject),
    .tp_itemsize = 0,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_new = PyType_GenericNew,
    .tp_init = (initproc)AES_CBC_init,
    .tp_methods = AES_CBC_methods,
};

// -----------------------------------------------------------------------------
// AES_CTR
// -----------------------------------------------------------------------------
typedef struct {
    PyObject_HEAD
    AES_Ctx_t ctx;
} AES_CTRObject;

static int AES_CTR_init(AES_CTRObject *self, PyObject *args, PyObject *kwds) {
    const char *key, *iv = NULL;
    Py_ssize_t key_len, iv_len = 0;
    AES_Mode_t mode;
    static char *kwlist[] = {"key", "iv", NULL};
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "y#|y#", kwlist, &key, &key_len, &iv, &iv_len)) return -1;
    if (!get_mode_from_keylen(key_len, &mode)) return -1;
    
    AES_Init_Ctx(&self->ctx, (const uint8_t*)key, mode);
    
    uint8_t iv_bytes[16] = {0};
    if (iv) {
        if (iv_len != 16) { PyErr_SetString(PyExc_ValueError, "IV must be 16 bytes"); return -1; }
        memcpy(iv_bytes, iv, 16);
    }
    uint32_t ctr_val = ((uint32_t)iv_bytes[12] << 24) | 
                       ((uint32_t)iv_bytes[13] << 16) | 
                       ((uint32_t)iv_bytes[14] << 8) | 
                       (uint32_t)iv_bytes[15];
    AES_CTR_Ctx_Set_Iv(&self->ctx, iv_bytes, ctr_val);
    return 0;
}

static PyObject* AES_CTR_set_iv(AES_CTRObject *self, PyObject *args, PyObject *kwds) {
    const char *iv = NULL;
    Py_ssize_t iv_len = 0;
    unsigned int ctr = 0;
    static char *kwlist[] = {"iv", "ctr", NULL};
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|y#I", kwlist, &iv, &iv_len, &ctr)) return NULL;
    uint8_t iv_bytes[16] = {0};
    if (iv) {
        if (iv_len != 16) { PyErr_SetString(PyExc_ValueError, "IV must be 16 bytes"); return NULL; }
        memcpy(iv_bytes, iv, 16);
    }
    
    uint32_t ctr_val = ctr;
    if (!ctr && iv) {
        ctr_val = ((uint32_t)iv_bytes[12] << 24) | 
                  ((uint32_t)iv_bytes[13] << 16) | 
                  ((uint32_t)iv_bytes[14] << 8) | 
                  (uint32_t)iv_bytes[15];
    }
    AES_CTR_Ctx_Set_Iv(&self->ctx, iv_bytes, ctr_val);
    Py_RETURN_NONE;
}

static PyObject* AES_CTR_crypt(AES_CTRObject *self, PyObject *args) {
    const char *data;
    Py_ssize_t data_len;
    if (!PyArg_ParseTuple(args, "y#", &data, &data_len)) return NULL;
    PyObject *out = PyBytes_FromStringAndSize(data, data_len);
    if (!out) return NULL;
    AES_CTR_Crypt(&self->ctx, (uint8_t*)PyBytes_AS_STRING(out), (uint32_t)data_len);
    return out;
}

static PyObject* AES_CTR_crypt_into(AES_CTRObject *self, PyObject *args) {
    Py_buffer buf;
    if (!PyArg_ParseTuple(args, "w*", &buf)) return NULL;
    AES_CTR_Crypt(&self->ctx, (uint8_t*)buf.buf, (uint32_t)buf.len);
    PyBuffer_Release(&buf);
    Py_RETURN_NONE;
}

static PyMethodDef AES_CTR_methods[] = {
    {"crypt", (PyCFunction)AES_CTR_crypt, METH_VARARGS, "Encrypt/Decrypt data in CTR mode (returns new bytes)"},
    {"crypt_into", (PyCFunction)AES_CTR_crypt_into, METH_VARARGS, "Encrypt/Decrypt writable buffer in-place"},
    {"set_iv", (PyCFunction)AES_CTR_set_iv, METH_VARARGS | METH_KEYWORDS, "Set IV and/or CTR"},
    {NULL}
};

static PyTypeObject AES_CTRType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "uaes.AES_CTR",
    .tp_doc = "AES CTR context",
    .tp_basicsize = sizeof(AES_CTRObject),
    .tp_itemsize = 0,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_new = PyType_GenericNew,
    .tp_init = (initproc)AES_CTR_init,
    .tp_methods = AES_CTR_methods,
};

// -----------------------------------------------------------------------------
// AES_GCM
// -----------------------------------------------------------------------------
typedef struct {
    PyObject_HEAD
    AES_GCM_Ctx_t ctx;
} AES_GCMObject;

static int AES_GCM_init(AES_GCMObject *self, PyObject *args, PyObject *kwds) {
    const char *key, *iv = NULL;
    Py_ssize_t key_len, iv_len = 0;
    AES_Mode_t mode;
    static char *kwlist[] = {"key", "iv", NULL};
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "y#|y#", kwlist, &key, &key_len, &iv, &iv_len)) return -1;
    if (!get_mode_from_keylen(key_len, &mode)) return -1;
    
    uint8_t iv_bytes[12] = {0};
    if (iv) {
        if (iv_len != 12) { PyErr_SetString(PyExc_ValueError, "GCM IV must be 12 bytes"); return -1; }
        memcpy(iv_bytes, iv, 12);
    }
    AES_GCM_Init_Ctx_Iv(&self->ctx, (const uint8_t*)key, iv_bytes, mode);
    return 0;
}

static PyObject* AES_GCM_set_iv(AES_GCMObject *self, PyObject *args) {
    const char *iv;
    Py_ssize_t iv_len;
    if (!PyArg_ParseTuple(args, "y#", &iv, &iv_len)) return NULL;
    if (iv_len != 12) { PyErr_SetString(PyExc_ValueError, "GCM IV must be 12 bytes"); return NULL; }
    AES_GCM_Ctx_Set_Iv(&self->ctx, (const uint8_t*)iv);
    Py_RETURN_NONE;
}

static PyObject* AES_GCM_encrypt(AES_GCMObject *self, PyObject *args, PyObject *kwds) {
    const char *data, *aad = NULL;
    Py_ssize_t data_len, aad_len = 0;
    int tag_len = 16;
    static char *kwlist[] = {"data", "aad", "tag_len", NULL};
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "y#|y#i", kwlist, &data, &data_len, &aad, &aad_len, &tag_len)) return NULL;
    
    PyObject *out = PyBytes_FromStringAndSize(data, data_len);
    PyObject *tag = PyBytes_FromStringAndSize(NULL, tag_len);
    if (!out || !tag) { Py_XDECREF(out); Py_XDECREF(tag); return NULL; }
    
    AES_GCM_Encrypt(&self->ctx, (uint8_t*)PyBytes_AS_STRING(out), (uint32_t)data_len, 
                          (const uint8_t*)aad, (uint32_t)aad_len, 
                          (uint8_t*)PyBytes_AS_STRING(tag), (uint8_t)tag_len);
                          
    PyObject *res = PyTuple_Pack(2, out, tag);
    Py_DECREF(out); Py_DECREF(tag);
    return res;
}

static PyObject* AES_GCM_decrypt(AES_GCMObject *self, PyObject *args, PyObject *kwds) {
    const char *data, *aad = NULL, *tag;
    Py_ssize_t data_len, aad_len = 0, tag_len;
    static char *kwlist[] = {"data", "tag", "aad", NULL};
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "y#y#|y#", kwlist, &data, &data_len, &tag, &tag_len, &aad, &aad_len)) return NULL;
    
    PyObject *out = PyBytes_FromStringAndSize(data, data_len);
    if (!out) return NULL;
    
    bool ok = AES_GCM_Decrypt(&self->ctx, (uint8_t*)PyBytes_AS_STRING(out), (uint32_t)data_len, 
                                    (const uint8_t*)aad, (uint32_t)aad_len, 
                                    (const uint8_t*)tag, (uint8_t)tag_len);
    if (!ok) {
        Py_DECREF(out);
        PyErr_SetString(PyExc_ValueError, "GCM authentication failed");
        return NULL;
    }
    return out;
}

static PyObject* AES_GCM_encrypt_into(AES_GCMObject *self, PyObject *args, PyObject *kwds) {
    Py_buffer buf;
    const char *aad = NULL;
    Py_ssize_t aad_len = 0;
    int tag_len = 16;
    static char *kwlist[] = {"data", "aad", "tag_len", NULL};
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "w*|y#i", kwlist, &buf, &aad, &aad_len, &tag_len)) return NULL;

    PyObject *tag = PyBytes_FromStringAndSize(NULL, tag_len);
    if (!tag) { PyBuffer_Release(&buf); return NULL; }

    AES_GCM_Encrypt(&self->ctx, (uint8_t*)buf.buf, (uint32_t)buf.len,
                          (const uint8_t*)aad, (uint32_t)aad_len,
                          (uint8_t*)PyBytes_AS_STRING(tag), (uint8_t)tag_len);
    PyBuffer_Release(&buf);
    return tag;
}

static PyObject* AES_GCM_decrypt_into(AES_GCMObject *self, PyObject *args, PyObject *kwds) {
    Py_buffer buf;
    const char *aad = NULL, *tag;
    Py_ssize_t aad_len = 0, tag_len;
    static char *kwlist[] = {"data", "tag", "aad", NULL};
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "w*y#|y#", kwlist, &buf, &tag, &tag_len, &aad, &aad_len)) return NULL;

    bool ok = AES_GCM_Decrypt(&self->ctx, (uint8_t*)buf.buf, (uint32_t)buf.len,
                                    (const uint8_t*)aad, (uint32_t)aad_len,
                                    (const uint8_t*)tag, (uint8_t)tag_len);
    PyBuffer_Release(&buf);
    if (!ok) {
        PyErr_SetString(PyExc_ValueError, "GCM authentication failed");
        return NULL;
    }
    Py_RETURN_NONE;
}

static PyMethodDef AES_GCM_methods[] = {
    {"encrypt", (PyCFunction)AES_GCM_encrypt, METH_VARARGS | METH_KEYWORDS, "Encrypt data in GCM mode (returns new bytes tuple)"},
    {"decrypt", (PyCFunction)AES_GCM_decrypt, METH_VARARGS | METH_KEYWORDS, "Decrypt data in GCM mode (returns new bytes)"},
    {"encrypt_into", (PyCFunction)AES_GCM_encrypt_into, METH_VARARGS | METH_KEYWORDS, "Encrypt buffer in-place, return tag"},
    {"decrypt_into", (PyCFunction)AES_GCM_decrypt_into, METH_VARARGS | METH_KEYWORDS, "Decrypt buffer in-place, verify tag"},
    {"set_iv", (PyCFunction)AES_GCM_set_iv, METH_VARARGS, "Set IV"},
    {NULL}
};

static PyTypeObject AES_GCMType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "uaes.AES_GCM",
    .tp_doc = "AES GCM context",
    .tp_basicsize = sizeof(AES_GCMObject),
    .tp_itemsize = 0,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_new = PyType_GenericNew,
    .tp_init = (initproc)AES_GCM_init,
    .tp_methods = AES_GCM_methods,
};

// -----------------------------------------------------------------------------
// AES_CMAC
// -----------------------------------------------------------------------------
typedef struct {
    PyObject_HEAD
    AES_CMAC_Ctx_t ctx;
} AES_CMACObject;

static int AES_CMAC_init(AES_CMACObject *self, PyObject *args, PyObject *kwds) {
    const char *key;
    Py_ssize_t key_len;
    AES_Mode_t mode;
    static char *kwlist[] = {"key", NULL};
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "y#", kwlist, &key, &key_len)) return -1;
    if (!get_mode_from_keylen(key_len, &mode)) return -1;
    AES_CMAC_Init(&self->ctx, (const uint8_t*)key, mode);
    return 0;
}

static PyObject* AES_CMAC_cmac(AES_CMACObject *self, PyObject *args, PyObject *kwds) {
    const char *data;
    Py_ssize_t data_len;
    int mac_len = 16;
    static char *kwlist[] = {"data", "mac_len", NULL};
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "y#|i", kwlist, &data, &data_len, &mac_len)) return NULL;
    
    PyObject *out = PyBytes_FromStringAndSize(NULL, mac_len);
    if (!out) return NULL;
    
    AES_CMAC(&self->ctx, (const uint8_t*)data, (uint32_t)data_len, (uint8_t*)PyBytes_AS_STRING(out), (uint_fast8_t)mac_len);
    return out;
}

static PyMethodDef AES_CMAC_methods[] = {
    {"cmac", (PyCFunction)AES_CMAC_cmac, METH_VARARGS | METH_KEYWORDS, "Calculate CMAC"},
    {NULL}
};

static PyTypeObject AES_CMACType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "uaes.AES_CMAC",
    .tp_doc = "AES CMAC context",
    .tp_basicsize = sizeof(AES_CMACObject),
    .tp_itemsize = 0,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_new = PyType_GenericNew,
    .tp_init = (initproc)AES_CMAC_init,
    .tp_methods = AES_CMAC_methods,
};

// -----------------------------------------------------------------------------
// Module Definition
// -----------------------------------------------------------------------------
static PyModuleDef uaesmodule = {
    PyModuleDef_HEAD_INIT,
    .m_name = "uaes",
    .m_doc = "Micro AES module.",
    .m_size = -1,
};

PyMODINIT_FUNC PyInit_uaes(void) {
    PyObject *m;
    
    if (PyType_Ready(&AES_ECBType) < 0) return NULL;
    if (PyType_Ready(&AES_CBCType) < 0) return NULL;
    if (PyType_Ready(&AES_CTRType) < 0) return NULL;
    if (PyType_Ready(&AES_GCMType) < 0) return NULL;
    if (PyType_Ready(&AES_CMACType) < 0) return NULL;
    
    m = PyModule_Create(&uaesmodule);
    if (m == NULL) return NULL;
    
    Py_INCREF(&AES_ECBType);
    if (PyModule_AddObject(m, "AES_ECB", (PyObject *) &AES_ECBType) < 0) { Py_DECREF(&AES_ECBType); Py_DECREF(m); return NULL; }
    
    Py_INCREF(&AES_CBCType);
    if (PyModule_AddObject(m, "AES_CBC", (PyObject *) &AES_CBCType) < 0) { Py_DECREF(&AES_CBCType); Py_DECREF(m); return NULL; }
    
    Py_INCREF(&AES_CTRType);
    if (PyModule_AddObject(m, "AES_CTR", (PyObject *) &AES_CTRType) < 0) { Py_DECREF(&AES_CTRType); Py_DECREF(m); return NULL; }
    
    Py_INCREF(&AES_GCMType);
    if (PyModule_AddObject(m, "AES_GCM", (PyObject *) &AES_GCMType) < 0) { Py_DECREF(&AES_GCMType); Py_DECREF(m); return NULL; }
    
    Py_INCREF(&AES_CMACType);
    if (PyModule_AddObject(m, "AES_CMAC", (PyObject *) &AES_CMACType) < 0) { Py_DECREF(&AES_CMACType); Py_DECREF(m); return NULL; }
    
    return m;
}
