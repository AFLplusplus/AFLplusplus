/*

This code is DEPRECATED!
I'm keeping it here cause maybe the uninstrumentation of a function is needed
for some strange reason.

*/

/*******************************************************************************
Copyright (c) 2019-2024, Andrea Fioraldi


Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*******************************************************************************/

#include "libqasan.h"
#include "map_macro.h"
#include <sys/types.h>
#include <pwd.h>

#define X_GET_FNPAR(type, name) name
#define GET_FNPAR(x) X_GET_FNPAR x
#define X_GET_FNTYPE(type, name) type
#define GET_FNTYPE(x) X_GET_FNTYPE x
#define X_GET_FNDECL(type, name) type name
#define GET_FNDECL(x) X_GET_FNDECL x

#define HOOK_UNINSTRUMENT(rettype, name, ...)                       \
  rettype (*__lq_libc_##name)(MAP_LIST(GET_FNTYPE, __VA_ARGS__));   \
  rettype name(MAP_LIST(GET_FNDECL, __VA_ARGS__)) {                 \
                                                                    \
    if (!(__lq_libc_##name)) __lq_libc_##name = ASSERT_DLSYM(name); \
    int     state = QASAN_SWAP(QASAN_DISABLED);                     \
    rettype r = __lq_libc_##name(MAP_LIST(GET_FNPAR, __VA_ARGS__)); \
    QASAN_SWAP(state);                                              \
                                                                    \
    return r;                                                       \
                                                                    \
  }

HOOK_UNINSTRUMENT(char *, getenv, (const char *, name))

/*
HOOK_UNINSTRUMENT(char*, setlocale, (int, category), (const char *, locale))
HOOK_UNINSTRUMENT(int, setenv, (const char *, name), (const char *, value),
(int, overwrite)) HOOK_UNINSTRUMENT(char*, getenv, (const char *, name))
HOOK_UNINSTRUMENT(char*, bindtextdomain, (const char *, domainname), (const char
*, dirname)) HOOK_UNINSTRUMENT(char*, bind_textdomain_codeset, (const char *,
domainname), (const char *, codeset)) HOOK_UNINSTRUMENT(char*, gettext, (const
char *, msgid)) HOOK_UNINSTRUMENT(char*, dgettext, (const char *, domainname),
(const char *, msgid)) HOOK_UNINSTRUMENT(char*, dcgettext, (const char *,
domainname), (const char *, msgid), (int, category)) HOOK_UNINSTRUMENT(int,
__gen_tempname, (char, *tmpl), (int, suffixlen), (int, flags), (int, kind))
HOOK_UNINSTRUMENT(int, mkstemp, (char *, template))
HOOK_UNINSTRUMENT(int, mkostemp, (char *, template), (int, flags))
HOOK_UNINSTRUMENT(int, mkstemps, (char *, template), (int, suffixlen))
HOOK_UNINSTRUMENT(int, mkostemps, (char *, template), (int, suffixlen), (int,
flags)) HOOK_UNINSTRUMENT(struct passwd *, getpwnam, (const char *, name))
HOOK_UNINSTRUMENT(struct passwd *, getpwuid, (uid_t, uid))
HOOK_UNINSTRUMENT(int, getpwnam_r, (const char *, name), (struct passwd *, pwd),
(char *, buf), (size_t, buflen), (struct passwd **, result))
HOOK_UNINSTRUMENT(int, getpwuid_r, (uid_t, uid), (struct passwd *, pwd), (char
*, buf), (size_t, buflen), (struct passwd **, result))
*/

