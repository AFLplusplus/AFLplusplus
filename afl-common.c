/*
 gather some functions common to multiple executables

 detect_file_args
 */

#include <stdlib.h>
#include <stdio.h>
#include <strings.h>

#include "debug.h"
#include "alloc-inl.h"

/* Detect @@ in args. */
#ifndef __glibc__
#include <unistd.h>
#endif
void detect_file_args(char** argv, u8* prog_in) {

  u32 i = 0;
#ifdef __GLIBC__
  u8* cwd = getcwd(NULL, 0); /* non portable glibc extension */
#else
  u8* cwd;
  char *buf;
  long size = pathconf(".", _PC_PATH_MAX);
  if ((buf = (char *)malloc((size_t)size)) != NULL) {
    cwd = getcwd(buf, (size_t)size); /* portable version */
  } else {
    PFATAL("getcwd() failed");
  }
#endif

  if (!cwd) PFATAL("getcwd() failed");

  while (argv[i]) {

    u8* aa_loc = strstr(argv[i], "@@");

    if (aa_loc) {

      u8 *aa_subst, *n_arg;

      if (!prog_in) FATAL("@@ syntax is not supported by this tool.");

      /* Be sure that we're always using fully-qualified paths. */

      if (prog_in[0] == '/') aa_subst = prog_in;
      else aa_subst = alloc_printf("%s/%s", cwd, prog_in);

      /* Construct a replacement argv value. */

      *aa_loc = 0;
      n_arg = alloc_printf("%s%s%s", argv[i], aa_subst, aa_loc + 2);
      argv[i] = n_arg;
      *aa_loc = '@';

      if (prog_in[0] != '/') ck_free(aa_subst);

    }

    i++;

  }

  free(cwd); /* not tracked */

}

