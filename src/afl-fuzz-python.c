/*
   american fuzzy lop++ - python extension routines
   ------------------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eißfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This is the real deal: the program takes an instrumented binary and
   attempts a variety of basic fuzzing tricks, paying close attention to
   how they affect the execution path.

 */

#include "afl-fuzz.h"

/* Python stuff */
#ifdef USE_PYTHON

int init_py_module(u8* module_name) {

  if (!module_name) return 1;

  Py_Initialize();

#if PY_MAJOR_VERSION >= 3
  PyObject* py_name = PyUnicode_FromString(module_name);
#else
  PyObject* py_name = PyString_FromString(module_name);
#endif

  py_module = PyImport_Import(py_name);
  Py_DECREF(py_name);

  if (py_module != NULL) {

    u8 py_notrim = 0, py_idx;
    py_functions[PY_FUNC_INIT] = PyObject_GetAttrString(py_module, "init");
    py_functions[PY_FUNC_FUZZ] = PyObject_GetAttrString(py_module, "fuzz");
    py_functions[PY_FUNC_PRE_SAVE] =
        PyObject_GetAttrString(py_module, "pre_save");
    py_functions[PY_FUNC_INIT_TRIM] =
        PyObject_GetAttrString(py_module, "init_trim");
    py_functions[PY_FUNC_POST_TRIM] =
        PyObject_GetAttrString(py_module, "post_trim");
    py_functions[PY_FUNC_TRIM] = PyObject_GetAttrString(py_module, "trim");

    for (py_idx = 0; py_idx < PY_FUNC_COUNT; ++py_idx) {

      if (!py_functions[py_idx] || !PyCallable_Check(py_functions[py_idx])) {

        if (py_idx == PY_FUNC_PRE_SAVE) {

          // Implenting the pre_save API is optional for now
          if (PyErr_Occurred()) PyErr_Print();

        } else if (py_idx >= PY_FUNC_INIT_TRIM && py_idx <= PY_FUNC_TRIM) {

          // Implementing the trim API is optional for now
          if (PyErr_Occurred()) PyErr_Print();
          py_notrim = 1;

        } else {

          if (PyErr_Occurred()) PyErr_Print();
          fprintf(stderr,
                  "Cannot find/call function with index %d in external "
                  "Python module.\n",
                  py_idx);
          return 1;

        }

      }

    }

    if (py_notrim) {

      py_functions[PY_FUNC_INIT_TRIM] = NULL;
      py_functions[PY_FUNC_POST_TRIM] = NULL;
      py_functions[PY_FUNC_TRIM] = NULL;
      WARNF(
          "Python module does not implement trim API, standard trimming will "
          "be used.");

    }

  } else {

    PyErr_Print();
    fprintf(stderr, "Failed to load \"%s\"\n", module_name);
    return 1;

  }

  return 0;

}

void finalize_py_module() {

  if (py_module != NULL) {

    u32 i;
    for (i = 0; i < PY_FUNC_COUNT; ++i)
      Py_XDECREF(py_functions[i]);

    Py_DECREF(py_module);

  }

  Py_Finalize();

}

void init_py(unsigned int seed) {
  PyObject *py_args, *py_value;

  /* Provide the init function a seed for the Python RNG */
  py_args = PyTuple_New(1);
#if PY_MAJOR_VERSION >= 3
  py_value = PyLong_FromLong(seed);
#else
  py_value = PyInt_FromLong(seed);
#endif

  if (!py_value) {

    Py_DECREF(py_args);
    fprintf(stderr, "Cannot convert argument\n");
    return;

  }

  PyTuple_SetItem(py_args, 0, py_value);

  py_value = PyObject_CallObject(py_functions[PY_FUNC_INIT], py_args);

  Py_DECREF(py_args);

  if (py_value == NULL) {

    PyErr_Print();
    fprintf(stderr, "Call failed\n");
    return;

  }
}

void fuzz_py_original(char* buf, size_t buflen,
                      char* add_buf, size_t add_buflen,
                      char** ret, size_t* retlen) {

  if (py_module != NULL) {

    PyObject *py_args, *py_value;
    py_args = PyTuple_New(2);
    py_value = PyByteArray_FromStringAndSize(buf, buflen);
    if (!py_value) {

      Py_DECREF(py_args);
      fprintf(stderr, "Cannot convert argument\n");
      return;

    }

    PyTuple_SetItem(py_args, 0, py_value);

    py_value = PyByteArray_FromStringAndSize(add_buf, add_buflen);
    if (!py_value) {

      Py_DECREF(py_args);
      fprintf(stderr, "Cannot convert argument\n");
      return;

    }

    PyTuple_SetItem(py_args, 1, py_value);

    py_value = PyObject_CallObject(py_functions[PY_FUNC_FUZZ], py_args);

    Py_DECREF(py_args);

    if (py_value != NULL) {

      *retlen = PyByteArray_Size(py_value);
      *ret = malloc(*retlen);
      memcpy(*ret, PyByteArray_AsString(py_value), *retlen);
      Py_DECREF(py_value);

    } else {

      PyErr_Print();
      fprintf(stderr, "Call failed\n");
      return;

    }

  }

}

size_t fuzz_py(u8* data, size_t size, u8* mutated_out, size_t max_size,
               unsigned int seed) {

  size_t out_size;
  PyObject *py_args, *py_value;
  py_args = PyTuple_New(3);

  py_value = PyByteArray_FromStringAndSize(data, size);
  if (!py_value) {

    Py_DECREF(py_args);
    FATAL("Failed to convert arguments");

  }

  PyTuple_SetItem(py_args, 0, py_value);

#if PY_MAJOR_VERSION >= 3
  py_value = PyLong_FromLong(max_size);
#else
  py_value = PyInt_FromLong(max_size);
#endif
  if (!py_value) {

    Py_DECREF(py_args);
    FATAL("Failed to convert arguments");

  }

  PyTuple_SetItem(py_args, 1, py_value);

#if PY_MAJOR_VERSION >= 3
  py_value = PyLong_FromLong(seed);
#else
  py_value = PyInt_FromLong(seed);
#endif
  if (!py_value) {

    Py_DECREF(py_args);
    FATAL("Failed to convert arguments");

  }

  PyTuple_SetItem(py_args, 2, py_value);

  py_value = PyObject_CallObject(py_functions[PY_FUNC_FUZZ], py_args);

  Py_DECREF(py_args);

  if (py_value != NULL) {

    out_size = PyByteArray_Size(py_value);
    memcpy(mutated_out, PyByteArray_AsString(py_value), out_size);
    Py_DECREF(py_value);

    return out_size;

  } else {

    PyErr_Print();
    FATAL("Call failed");

  }

}

size_t pre_save_py(u8* data, size_t size, u8** new_data) {

  size_t new_size;
  PyObject *py_args, *py_value;
  py_args = PyTuple_New(2);
  py_value = PyByteArray_FromStringAndSize(data, size);
  if (!py_value) {

    Py_DECREF(py_args);
    FATAL("Failed to convert arguments");

  }

  PyTuple_SetItem(py_args, 0, py_value);

  py_value = PyObject_CallObject(py_functions[PY_FUNC_PRE_SAVE], py_args);

  Py_DECREF(py_args);

  if (py_value != NULL) {

    new_size = PyByteArray_Size(py_value);
    *new_data = malloc(new_size);
    memcpy(*new_data, PyByteArray_AsString(py_value), new_size);
    Py_DECREF(py_value);
    return new_size;

  } else {

    PyErr_Print();
    FATAL("Call failed");

  }

}

u32 init_trim_py(u8* buf, size_t buflen) {

  PyObject *py_args, *py_value;

  py_args = PyTuple_New(1);
  py_value = PyByteArray_FromStringAndSize(buf, buflen);
  if (!py_value) {

    Py_DECREF(py_args);
    FATAL("Failed to convert arguments");

  }

  PyTuple_SetItem(py_args, 0, py_value);

  py_value = PyObject_CallObject(py_functions[PY_FUNC_INIT_TRIM], py_args);
  Py_DECREF(py_args);

  if (py_value != NULL) {

#if PY_MAJOR_VERSION >= 3
    u32 retcnt = (u32)PyLong_AsLong(py_value);
#else
    u32 retcnt = PyInt_AsLong(py_value);
#endif
    Py_DECREF(py_value);
    return retcnt;

  } else {

    PyErr_Print();
    FATAL("Call failed");

  }

}

u32 post_trim_py(u8 success) {

  PyObject *py_args, *py_value;

  py_args = PyTuple_New(1);

  py_value = PyBool_FromLong(success);
  if (!py_value) {

    Py_DECREF(py_args);
    FATAL("Failed to convert arguments");

  }

  PyTuple_SetItem(py_args, 0, py_value);

  py_value = PyObject_CallObject(py_functions[PY_FUNC_POST_TRIM], py_args);
  Py_DECREF(py_args);

  if (py_value != NULL) {

#if PY_MAJOR_VERSION >= 3
    u32 retcnt = (u32)PyLong_AsLong(py_value);
#else
    u32 retcnt = PyInt_AsLong(py_value);
#endif
    Py_DECREF(py_value);
    return retcnt;

  } else {

    PyErr_Print();
    FATAL("Call failed");

  }

}

void trim_py(u8** ret, size_t* retlen) {

  PyObject *py_args, *py_value;

  py_args = PyTuple_New(0);
  py_value = PyObject_CallObject(py_functions[PY_FUNC_TRIM], py_args);
  Py_DECREF(py_args);

  if (py_value != NULL) {

    *retlen = PyByteArray_Size(py_value);
    *ret = malloc(*retlen);
    memcpy(*ret, PyByteArray_AsString(py_value), *retlen);
    Py_DECREF(py_value);

  } else {

    PyErr_Print();
    FATAL("Call failed");

  }

}

#endif                                                        /* USE_PYTHON */

