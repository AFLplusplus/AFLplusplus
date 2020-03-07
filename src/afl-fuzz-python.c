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
    py_functions[PY_FUNC_HAVOC_MUTATION] =
        PyObject_GetAttrString(py_module, "havoc_mutation");
    py_functions[PY_FUNC_HAVOC_MUTATION_PROBABILITY] =
        PyObject_GetAttrString(py_module, "havoc_mutation_probability");
    py_functions[PY_FUNC_QUEUE_GET] =
        PyObject_GetAttrString(py_module, "queue_get");
    py_functions[PY_FUNC_QUEUE_NEW_ENTRY] =
        PyObject_GetAttrString(py_module, "queue_new_entry");

    for (py_idx = 0; py_idx < PY_FUNC_COUNT; ++py_idx) {

      if (!py_functions[py_idx] || !PyCallable_Check(py_functions[py_idx])) {

        if (py_idx == PY_FUNC_PRE_SAVE) {

          // Implenting the pre_save API is optional for now
          if (PyErr_Occurred()) PyErr_Print();

        } else if (py_idx >= PY_FUNC_INIT_TRIM && py_idx <= PY_FUNC_TRIM) {

          // Implementing the trim API is optional for now
          if (PyErr_Occurred()) PyErr_Print();
          py_notrim = 1;

        } else if ((py_idx >= PY_FUNC_HAVOC_MUTATION) &&
                   (py_idx <= PY_FUNC_QUEUE_NEW_ENTRY)) {

          // Implenting the havoc and queue API is optional for now
          if (PyErr_Occurred()) PyErr_Print();

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

size_t fuzz_py(u8** buf, size_t buf_size, u8* add_buf, size_t add_buf_size,
               size_t max_size) {

  size_t mutated_size;
  PyObject *py_args, *py_value;
  py_args = PyTuple_New(3);

  /* buf */
  py_value = PyByteArray_FromStringAndSize(*buf, buf_size);
  if (!py_value) {

    Py_DECREF(py_args);
    FATAL("Failed to convert arguments");

  }

  PyTuple_SetItem(py_args, 0, py_value);

  /* add_buf */
  py_value = PyByteArray_FromStringAndSize(add_buf, add_buf_size);
  if (!py_value) {

    Py_DECREF(py_args);
    FATAL("Failed to convert arguments");

  }

  PyTuple_SetItem(py_args, 1, py_value);

  /* max_size */
#if PY_MAJOR_VERSION >= 3
  py_value = PyLong_FromLong(max_size);
#else
  py_value = PyInt_FromLong(max_size);
#endif
  if (!py_value) {

    Py_DECREF(py_args);
    FATAL("Failed to convert arguments");

  }

  PyTuple_SetItem(py_args, 2, py_value);

  py_value = PyObject_CallObject(py_functions[PY_FUNC_FUZZ], py_args);

  Py_DECREF(py_args);

  if (py_value != NULL) {

    mutated_size = PyByteArray_Size(py_value);
    if (buf_size < mutated_size)
      *buf = ck_realloc(*buf, mutated_size);

    memcpy(*buf, PyByteArray_AsString(py_value), mutated_size);
    Py_DECREF(py_value);
    return mutated_size;

  } else {

    PyErr_Print();
    FATAL("Call failed");

  }

}

size_t pre_save_py(u8* buf, size_t buf_size, u8** out_buf) {

  size_t out_buf_size;
  PyObject *py_args, *py_value;
  py_args = PyTuple_New(2);
  py_value = PyByteArray_FromStringAndSize(buf, buf_size);
  if (!py_value) {

    Py_DECREF(py_args);
    FATAL("Failed to convert arguments");

  }

  PyTuple_SetItem(py_args, 0, py_value);

  py_value = PyObject_CallObject(py_functions[PY_FUNC_PRE_SAVE], py_args);

  Py_DECREF(py_args);

  if (py_value != NULL) {

    out_buf_size = PyByteArray_Size(py_value);
    *out_buf = malloc(out_buf_size);
    memcpy(*out_buf, PyByteArray_AsString(py_value), out_buf_size);
    Py_DECREF(py_value);
    return out_buf_size;

  } else {

    PyErr_Print();
    FATAL("Call failed");

  }

}

u32 init_trim_py(u8* buf, size_t buf_size) {

  PyObject *py_args, *py_value;

  py_args = PyTuple_New(1);
  py_value = PyByteArray_FromStringAndSize(buf, buf_size);
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

void trim_py(u8** out_buf, size_t* out_buf_size) {

  PyObject *py_args, *py_value;

  py_args = PyTuple_New(0);
  py_value = PyObject_CallObject(py_functions[PY_FUNC_TRIM], py_args);
  Py_DECREF(py_args);

  if (py_value != NULL) {

    *out_buf_size = PyByteArray_Size(py_value);
    *out_buf = malloc(*out_buf_size);
    memcpy(*out_buf, PyByteArray_AsString(py_value), *out_buf_size);
    Py_DECREF(py_value);

  } else {

    PyErr_Print();
    FATAL("Call failed");

  }

}

size_t havoc_mutation_py(u8** buf, size_t buf_size, size_t max_size) {

  size_t mutated_size;
  PyObject *py_args, *py_value;
  py_args = PyTuple_New(2);

  /* buf */
  py_value = PyByteArray_FromStringAndSize(*buf, buf_size);
  if (!py_value) {

    Py_DECREF(py_args);
    FATAL("Failed to convert arguments");

  }

  PyTuple_SetItem(py_args, 0, py_value);

  /* max_size */
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

  py_value = PyObject_CallObject(py_functions[PY_FUNC_HAVOC_MUTATION], py_args);

  Py_DECREF(py_args);

  if (py_value != NULL) {

    mutated_size = PyByteArray_Size(py_value);
    if (buf_size < mutated_size)
      *buf = ck_realloc(*buf, mutated_size);
    
    memcpy(*buf, PyByteArray_AsString(py_value), mutated_size);

    Py_DECREF(py_value);
    return mutated_size;

  } else {

    PyErr_Print();
    FATAL("Call failed");

  }

}

u8 havoc_mutation_probability_py(void) {

  PyObject *py_args, *py_value;

  py_args = PyTuple_New(0);
  py_value = PyObject_CallObject(py_functions[PY_FUNC_HAVOC_MUTATION_PROBABILITY], py_args);
  Py_DECREF(py_args);

  if (py_value != NULL) {

    long prob = PyLong_AsLong(py_value);
    Py_DECREF(py_value);
    return (u8)prob;

  } else {

    PyErr_Print();
    FATAL("Call failed");

  }

}

u8 queue_get_py(const u8* filename) {

  PyObject *py_args, *py_value;

  py_args = PyTuple_New(1);

  // File name
#if PY_MAJOR_VERSION >= 3
  py_value = PyUnicode_FromString(filename);
#else
  py_value = PyString_FromString(filename);
#endif
  if (!py_value) {

    Py_DECREF(py_args);
    FATAL("Failed to convert arguments");

  }

  PyTuple_SetItem(py_args, 0, py_value);

  // Call Python function
  py_value = PyObject_CallObject(py_functions[PY_FUNC_QUEUE_GET], py_args);
  Py_DECREF(py_args);

  if (py_value != NULL) {

    int ret = PyObject_IsTrue(py_value);
    Py_DECREF(py_value);
    
    if (ret == -1) {

      PyErr_Print();
      FATAL("Failed to convert return value");

    }

    return (u8) ret & 0xFF;

  } else {
    
    PyErr_Print();
    FATAL("Call failed");

  }

}

void queue_new_entry_py(const u8* filename_new_queue,
                        const u8* filename_orig_queue) {

  PyObject *py_args, *py_value;

  py_args = PyTuple_New(2);

  // New queue
#if PY_MAJOR_VERSION >= 3
  py_value = PyUnicode_FromString(filename_new_queue);
#else
  py_value = PyString_FromString(filename_new_queue);
#endif
  if (!py_value) {
  
    Py_DECREF(py_args);
    FATAL("Failed to convert arguments");

  }

  PyTuple_SetItem(py_args, 0, py_value);

  // Orig queue
  py_value = Py_None;
  if (filename_orig_queue) {

#if PY_MAJOR_VERSION >= 3
    py_value = PyUnicode_FromString(filename_orig_queue);
#else
    py_value = PyString_FromString(filename_orig_queue);
#endif
    if (!py_value) {
 
      Py_DECREF(py_args);
      FATAL("Failed to convert arguments");

    }

  }

  PyTuple_SetItem(py_args, 1, py_value);

  // Call
  py_value = PyObject_CallObject(py_functions[PY_FUNC_QUEUE_NEW_ENTRY],
                                 py_args);
  Py_DECREF(py_args);

  if (py_value == NULL) {

    PyErr_Print();
    FATAL("Call failed");

  }

}

#endif                                                        /* USE_PYTHON */

