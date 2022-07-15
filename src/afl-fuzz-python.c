/*
   american fuzzy lop++ - python extension routines
   ------------------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eißfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2022 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   This is the real deal: the program takes an instrumented binary and
   attempts a variety of basic fuzzing tricks, paying close attention to
   how they affect the execution path.

 */

#include "afl-fuzz.h"

/* Python stuff */
#ifdef USE_PYTHON

// Tries to cast a python bytearray or bytes to a char ptr
static inline bool py_bytes(PyObject *py_value, /* out */ char **bytes,
                            /* out */ size_t *size) {

  if (!py_value) { return false; }

  *bytes = PyByteArray_AsString(py_value);
  if (*bytes) {

    // we got a bytearray
    *size = PyByteArray_Size(py_value);

  } else {

    *bytes = PyBytes_AsString(py_value);
    if (!*bytes) {

      // No valid type returned.
      return false;

    }

    *size = PyBytes_Size(py_value);

  }

  return true;

}

static void *unsupported(afl_state_t *afl, unsigned int seed) {

  (void)afl;
  (void)seed;

  FATAL("Python Mutator cannot be called twice yet");
  return NULL;

}

  /* sorry for this makro...
  it just fills in `&py_mutator->something_buf, &py_mutator->something_size`. */
  #define BUF_PARAMS(name) (void **)&((py_mutator_t *)py_mutator)->name##_buf

static size_t fuzz_py(void *py_mutator, u8 *buf, size_t buf_size, u8 **out_buf,
                      u8 *add_buf, size_t add_buf_size, size_t max_size) {

  size_t    mutated_size;
  PyObject *py_args, *py_value;
  py_args = PyTuple_New(3);
  py_mutator_t *py = (py_mutator_t *)py_mutator;

  /* buf */
  py_value = PyByteArray_FromStringAndSize(buf, buf_size);
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

  py_value = PyObject_CallObject(py->py_functions[PY_FUNC_FUZZ], py_args);

  Py_DECREF(py_args);

  if (py_value != NULL) {

    char *bytes;
    if (!py_bytes(py_value, &bytes, &mutated_size)) {

      FATAL("Python mutator fuzz() should return a bytearray or bytes");

    }

    if (mutated_size) {

      *out_buf = afl_realloc(BUF_PARAMS(fuzz), mutated_size);
      if (unlikely(!*out_buf)) { PFATAL("alloc"); }

      memcpy(*out_buf, bytes, mutated_size);

    }

    Py_DECREF(py_value);
    return mutated_size;

  } else {

    PyErr_Print();
    FATAL("python custom fuzz: call failed");

  }

}

static const char *custom_describe_py(void  *py_mutator,
                                      size_t max_description_len) {

  PyObject *py_args, *py_value;

  py_args = PyTuple_New(1);

  PyLong_FromSize_t(max_description_len);

  /* add_buf */
  py_value = PyLong_FromSize_t(max_description_len);
  if (!py_value) {

    Py_DECREF(py_args);
    FATAL("Failed to convert arguments");

  }

  PyTuple_SetItem(py_args, 0, py_value);

  py_value = PyObject_CallObject(
      ((py_mutator_t *)py_mutator)->py_functions[PY_FUNC_DESCRIBE], py_args);

  Py_DECREF(py_args);

  if (py_value != NULL) { return PyBytes_AsString(py_value); }

  return NULL;

}

static py_mutator_t *init_py_module(afl_state_t *afl, u8 *module_name) {

  (void)afl;

  if (!module_name) { return NULL; }

  py_mutator_t *py = calloc(1, sizeof(py_mutator_t));
  if (!py) { PFATAL("Could not allocate memory for python mutator!"); }

  Py_Initialize();

  #if PY_MAJOR_VERSION >= 3
  PyObject *py_name = PyUnicode_FromString(module_name);
  #else
  PyObject *py_name = PyString_FromString(module_name);
  #endif

  py->py_module = PyImport_Import(py_name);
  Py_DECREF(py_name);

  PyObject  *py_module = py->py_module;
  PyObject **py_functions = py->py_functions;

  // initialize the post process buffer; ensures it's always valid
  PyObject *unused_bytes = PyByteArray_FromStringAndSize("OHAI", 4);
  if (!unused_bytes) { FATAL("allocation failed!"); }
  if (PyObject_GetBuffer(unused_bytes, &py->post_process_buf, PyBUF_SIMPLE) ==
      -1) {

    FATAL("buffer initialization failed");

  }

  Py_DECREF(unused_bytes);

  if (py_module != NULL) {

    u8 py_notrim = 0, py_idx;
    /* init, required */
    py_functions[PY_FUNC_INIT] = PyObject_GetAttrString(py_module, "init");
    if (!py_functions[PY_FUNC_INIT])
      FATAL("init function not found in python module");
    py_functions[PY_FUNC_FUZZ] = PyObject_GetAttrString(py_module, "fuzz");
    if (!py_functions[PY_FUNC_FUZZ])
      py_functions[PY_FUNC_FUZZ] = PyObject_GetAttrString(py_module, "mutate");
    py_functions[PY_FUNC_DESCRIBE] =
        PyObject_GetAttrString(py_module, "describe");
    py_functions[PY_FUNC_FUZZ_COUNT] =
        PyObject_GetAttrString(py_module, "fuzz_count");
    if (!py_functions[PY_FUNC_FUZZ])
      WARNF("fuzz function not found in python module");
    py_functions[PY_FUNC_POST_PROCESS] =
        PyObject_GetAttrString(py_module, "post_process");
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
    py_functions[PY_FUNC_INTROSPECTION] =
        PyObject_GetAttrString(py_module, "introspection");
    py_functions[PY_FUNC_DEINIT] = PyObject_GetAttrString(py_module, "deinit");
    if (!py_functions[PY_FUNC_DEINIT])
      WARNF("deinit function not found in python module");

    for (py_idx = 0; py_idx < PY_FUNC_COUNT; ++py_idx) {

      if (!py_functions[py_idx] || !PyCallable_Check(py_functions[py_idx])) {

        if (py_idx >= PY_FUNC_INIT_TRIM && py_idx <= PY_FUNC_TRIM) {

          // Implementing the trim API is optional for now
          if (PyErr_Occurred()) { PyErr_Print(); }
          py_notrim = 1;

        } else if (py_idx >= PY_OPTIONAL) {

          // Only _init and _deinit are not optional currently

          if (PyErr_Occurred()) { PyErr_Print(); }

        } else {

          fprintf(stderr,
                  "Cannot find/call function with index %d in external "
                  "Python module.\n",
                  py_idx);
          return NULL;

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
    free(py);
    return NULL;

  }

  return py;

}

void finalize_py_module(void *py_mutator) {

  py_mutator_t *py = (py_mutator_t *)py_mutator;

  if (py->py_module != NULL) {

    deinit_py(py_mutator);

    u32 i;
    for (i = 0; i < PY_FUNC_COUNT; ++i) {

      Py_XDECREF(py->py_functions[i]);

    }

    Py_DECREF(py->py_module);

  }

  Py_Finalize();

}

static void init_py(afl_state_t *afl, py_mutator_t *py_mutator,
                    unsigned int seed) {

  (void)afl;

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
    FATAL("Cannot convert argument in python init.");

  }

  PyTuple_SetItem(py_args, 0, py_value);

  py_value =
      PyObject_CallObject(py_mutator->py_functions[PY_FUNC_INIT], py_args);

  Py_DECREF(py_args);

  if (py_value == NULL) {

    PyErr_Print();
    fprintf(stderr, "Call failed\n");
    FATAL("Custom py mutator INIT failed.");

  }

}

void deinit_py(void *py_mutator) {

  PyObject *py_args, *py_value;

  py_args = PyTuple_New(0);
  py_value = PyObject_CallObject(
      ((py_mutator_t *)py_mutator)->py_functions[PY_FUNC_DEINIT], py_args);
  Py_DECREF(py_args);

  if (py_value != NULL) {

    Py_DECREF(py_value);

  } else {

    PyErr_Print();
    FATAL("Call failed");

  }

}

struct custom_mutator *load_custom_mutator_py(afl_state_t *afl,
                                              char        *module_name) {

  struct custom_mutator *mutator;

  mutator = ck_alloc(sizeof(struct custom_mutator));

  mutator->name = module_name;
  ACTF("Loading Python mutator library from '%s'...", module_name);

  py_mutator_t *py_mutator;
  py_mutator = init_py_module(afl, module_name);
  mutator->data = py_mutator;
  if (!py_mutator) { FATAL("Failed to load python mutator."); }

  PyObject **py_functions = py_mutator->py_functions;

  if (py_functions[PY_FUNC_INIT]) { mutator->afl_custom_init = unsupported; }

  if (py_functions[PY_FUNC_DEINIT]) { mutator->afl_custom_deinit = deinit_py; }

  if (py_functions[PY_FUNC_FUZZ]) { mutator->afl_custom_fuzz = fuzz_py; }

  if (py_functions[PY_FUNC_DESCRIBE]) {

    mutator->afl_custom_describe = custom_describe_py;

  }

  if (py_functions[PY_FUNC_POST_PROCESS]) {

    mutator->afl_custom_post_process = post_process_py;

  }

  if (py_functions[PY_FUNC_INIT_TRIM]) {

    mutator->afl_custom_init_trim = init_trim_py;

  }

  if (py_functions[PY_FUNC_FUZZ_COUNT]) {

    mutator->afl_custom_fuzz_count = fuzz_count_py;

  }

  if (py_functions[PY_FUNC_POST_TRIM]) {

    mutator->afl_custom_post_trim = post_trim_py;

  }

  if (py_functions[PY_FUNC_TRIM]) { mutator->afl_custom_trim = trim_py; }

  if (py_functions[PY_FUNC_HAVOC_MUTATION]) {

    mutator->afl_custom_havoc_mutation = havoc_mutation_py;

  }

  if (py_functions[PY_FUNC_HAVOC_MUTATION_PROBABILITY]) {

    mutator->afl_custom_havoc_mutation_probability =
        havoc_mutation_probability_py;

  }

  if (py_functions[PY_FUNC_QUEUE_GET]) {

    mutator->afl_custom_queue_get = queue_get_py;

  }

  if (py_functions[PY_FUNC_QUEUE_NEW_ENTRY]) {

    mutator->afl_custom_queue_new_entry = queue_new_entry_py;

  }

  #ifdef INTROSPECTION
  if (py_functions[PY_FUNC_INTROSPECTION]) {

    mutator->afl_custom_introspection = introspection_py;

  }

  #endif

  OKF("Python mutator '%s' installed successfully.", module_name);

  /* Initialize the custom mutator */
  init_py(afl, py_mutator, rand_below(afl, 0xFFFFFFFF));

  mutator->stacked_custom = (mutator && mutator->afl_custom_havoc_mutation);
  mutator->stacked_custom_prob =
      6;  // like one of the default mutations in havoc

  return mutator;

}

size_t post_process_py(void *py_mutator, u8 *buf, size_t buf_size,
                       u8 **out_buf) {

  PyObject     *py_args, *py_value;
  py_mutator_t *py = (py_mutator_t *)py_mutator;

  // buffer returned previously must be released; initialized during init
  // so we don't need to do comparisons
  PyBuffer_Release(&py->post_process_buf);

  py_args = PyTuple_New(1);
  py_value = PyByteArray_FromStringAndSize(buf, buf_size);
  if (!py_value) {

    Py_DECREF(py_args);
    FATAL("Failed to convert arguments in custom post_process");

  }

  PyTuple_SetItem(py_args, 0, py_value);

  py_value = PyObject_CallObject(
      ((py_mutator_t *)py_mutator)->py_functions[PY_FUNC_POST_PROCESS],
      py_args);

  Py_DECREF(py_args);

  if (py_value != NULL) {

    if (PyObject_GetBuffer(py_value, &py->post_process_buf, PyBUF_SIMPLE) ==
        -1) {

      PyErr_Print();
      FATAL(
          "Python custom mutator: post_process call return value not a "
          "bytes-like object");

    }

    Py_DECREF(py_value);

    *out_buf = (u8 *)py->post_process_buf.buf;
    return py->post_process_buf.len;

  } else {

    PyErr_Print();
    FATAL("Python custom mutator: post_process call failed.");

  }

}

s32 init_trim_py(void *py_mutator, u8 *buf, size_t buf_size) {

  PyObject *py_args, *py_value;

  py_args = PyTuple_New(1);
  py_value = PyByteArray_FromStringAndSize(buf, buf_size);
  if (!py_value) {

    Py_DECREF(py_args);
    FATAL("Failed to convert arguments");

  }

  PyTuple_SetItem(py_args, 0, py_value);

  py_value = PyObject_CallObject(
      ((py_mutator_t *)py_mutator)->py_functions[PY_FUNC_INIT_TRIM], py_args);
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

u32 fuzz_count_py(void *py_mutator, const u8 *buf, size_t buf_size) {

  PyObject *py_args, *py_value;

  py_args = PyTuple_New(1);
  py_value = PyByteArray_FromStringAndSize(buf, buf_size);
  if (!py_value) {

    Py_DECREF(py_args);
    FATAL("Failed to convert arguments");

  }

  PyTuple_SetItem(py_args, 0, py_value);

  py_value = PyObject_CallObject(
      ((py_mutator_t *)py_mutator)->py_functions[PY_FUNC_FUZZ_COUNT], py_args);
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

s32 post_trim_py(void *py_mutator, u8 success) {

  PyObject *py_args, *py_value;

  py_args = PyTuple_New(1);

  py_value = PyBool_FromLong(success);
  if (!py_value) {

    Py_DECREF(py_args);
    FATAL("Failed to convert arguments");

  }

  PyTuple_SetItem(py_args, 0, py_value);

  py_value = PyObject_CallObject(
      ((py_mutator_t *)py_mutator)->py_functions[PY_FUNC_POST_TRIM], py_args);
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

size_t trim_py(void *py_mutator, u8 **out_buf) {

  PyObject *py_args, *py_value;
  size_t    trimmed_size;

  py_args = PyTuple_New(0);
  py_value = PyObject_CallObject(
      ((py_mutator_t *)py_mutator)->py_functions[PY_FUNC_TRIM], py_args);
  Py_DECREF(py_args);

  if (py_value != NULL) {

    char *bytes;
    if (!py_bytes(py_value, &bytes, &trimmed_size)) {

      FATAL("Python mutator fuzz() should return a bytearray");

    }

    if (trimmed_size) {

      *out_buf = afl_realloc(BUF_PARAMS(trim), trimmed_size);
      if (unlikely(!*out_buf)) { PFATAL("alloc"); }
      memcpy(*out_buf, bytes, trimmed_size);

    }

    Py_DECREF(py_value);

  } else {

    PyErr_Print();
    FATAL("Call failed");

  }

  return trimmed_size;

}

size_t havoc_mutation_py(void *py_mutator, u8 *buf, size_t buf_size,
                         u8 **out_buf, size_t max_size) {

  size_t    mutated_size;
  PyObject *py_args, *py_value;
  py_args = PyTuple_New(2);

  /* buf */
  py_value = PyByteArray_FromStringAndSize(buf, buf_size);
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

  py_value = PyObject_CallObject(
      ((py_mutator_t *)py_mutator)->py_functions[PY_FUNC_HAVOC_MUTATION],
      py_args);

  Py_DECREF(py_args);

  if (py_value != NULL) {

    char *bytes;
    if (!py_bytes(py_value, &bytes, &mutated_size)) {

      FATAL("Python mutator fuzz() should return a bytearray");

    }

    if (mutated_size <= buf_size) {

      /* We reuse the input buf here. */
      *out_buf = buf;

    } else {

      /* A new buf is needed... */
      *out_buf = afl_realloc(BUF_PARAMS(havoc), mutated_size);
      if (unlikely(!*out_buf)) { PFATAL("alloc"); }

    }

    if (mutated_size) { memcpy(*out_buf, bytes, mutated_size); }

    Py_DECREF(py_value);
    return mutated_size;

  } else {

    PyErr_Print();
    FATAL("Call failed");

  }

}

u8 havoc_mutation_probability_py(void *py_mutator) {

  PyObject *py_args, *py_value;

  py_args = PyTuple_New(0);
  py_value = PyObject_CallObject(
      ((py_mutator_t *)py_mutator)
          ->py_functions[PY_FUNC_HAVOC_MUTATION_PROBABILITY],
      py_args);
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

const char *introspection_py(void *py_mutator) {

  PyObject *py_args, *py_value;

  py_args = PyTuple_New(0);
  py_value = PyObject_CallObject(
      ((py_mutator_t *)py_mutator)->py_functions[PY_FUNC_INTROSPECTION],
      py_args);
  Py_DECREF(py_args);

  if (py_value == NULL) {

    return NULL;

  } else {

    char  *ret;
    size_t len;
    if (!py_bytes(py_value, &ret, &len)) {

      FATAL(
          "Python mutator introspection call returned illegal type (expected "
          "bytes or bytearray)");

    }

    return ret;

  }

}

u8 queue_get_py(void *py_mutator, const u8 *filename) {

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
  py_value = PyObject_CallObject(
      ((py_mutator_t *)py_mutator)->py_functions[PY_FUNC_QUEUE_GET], py_args);
  Py_DECREF(py_args);

  if (py_value != NULL) {

    int ret = PyObject_IsTrue(py_value);
    Py_DECREF(py_value);

    if (ret == -1) {

      PyErr_Print();
      FATAL("Failed to convert return value");

    }

    return (u8)ret & 0xFF;

  } else {

    PyErr_Print();
    FATAL("Call failed");

  }

}

u8 queue_new_entry_py(void *py_mutator, const u8 *filename_new_queue,
                      const u8 *filename_orig_queue) {

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
  py_value = PyObject_CallObject(
      ((py_mutator_t *)py_mutator)->py_functions[PY_FUNC_QUEUE_NEW_ENTRY],
      py_args);
  Py_DECREF(py_args);

  if (py_value != NULL) {

    int ret = PyObject_IsTrue(py_value);
    Py_DECREF(py_value);

    if (ret == -1) {

      PyErr_Print();
      FATAL("Failed to convert return value");

    }

    return (u8)ret & 0xFF;

  } else {

    PyErr_Print();
    FATAL("Call failed");

  }

}

  #undef BUF_PARAMS

#endif                                                        /* USE_PYTHON */

