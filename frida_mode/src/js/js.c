#include "frida-gumjs.h"

#include "js.h"
#include "util.h"

gboolean                  js_done = FALSE;
js_api_stalker_callback_t js_user_callback = NULL;
js_main_hook_t            js_main_hook = NULL;

static char               *js_script = NULL;
static gchar              *filename = "afl.js";
static gchar              *contents;
static GumScriptBackend   *backend;
static GCancellable       *cancellable = NULL;
static GError             *error = NULL;
static GumScript          *script;
static GumScriptScheduler *scheduler;
static GMainContext       *context;
static GMainLoop          *main_loop;

static void js_msg(GumScript *script, const gchar *message, GBytes *data,
                   gpointer user_data) {

  UNUSED_PARAMETER(script);
  UNUSED_PARAMETER(data);
  UNUSED_PARAMETER(user_data);
  FOKF("%s", message);

}

void js_config(void) {

  js_script = getenv("AFL_FRIDA_JS_SCRIPT");

}

static gchar *js_get_script() {

  gsize length;
  if (js_script != NULL) { filename = js_script; }

  filename = g_canonicalize_filename(filename, g_get_current_dir());

  if (!g_file_get_contents(filename, &contents, &length, NULL)) {

    if (js_script == NULL) {

      return NULL;

    } else {

      FFATAL("Could not load script file: %s", filename);

    }

  } else {

    FOKF(cBLU "Javascript" cRST " - " cGRN "script:" cYEL " [%s]",
         filename == NULL ? " " : filename);
    FOKF(cBLU "Javascript" cRST " - " cGRN "size: " cYEL "%" G_GSIZE_MODIFIER
              "d bytes",
         length);

    gchar *source = g_malloc0(api_js_len + length + 1);
    memcpy(source, api_js, api_js_len);
    memcpy(&source[api_js_len], contents, length);

    return source;

  }

}

static void js_print_script(gchar *source) {

  gchar **split = g_strsplit(source, "\n", 0);

  for (size_t i = 0; split[i] != NULL; i++) {

    FVERBOSE("%3" G_GSIZE_MODIFIER "d. %s", i + 1, split[i]);

  }

  g_strfreev(split);

}

static void load_cb(GObject *source_object, GAsyncResult *result,
                    gpointer user_data) {

  UNUSED_PARAMETER(source_object);
  UNUSED_PARAMETER(user_data);
  gum_script_load_finish(script, result);
  if (error != NULL) { FFATAL("Failed to load script - %s", error->message); }

}

static void create_cb(GObject *source_object, GAsyncResult *result,
                      gpointer user_data) {

  UNUSED_PARAMETER(source_object);
  UNUSED_PARAMETER(user_data);
  script = gum_script_backend_create_finish(backend, result, &error);
  if (error != NULL) { FFATAL("Failed to create script: %s", error->message); }

  gum_script_set_message_handler(script, js_msg, NULL, NULL);

  gum_script_load(script, cancellable, load_cb, NULL);

}

void js_start(void) {

  gchar *source = js_get_script();
  if (source == NULL) { return; }
  js_print_script(source);

  scheduler = gum_script_backend_get_scheduler();
  gum_script_scheduler_disable_background_thread(scheduler);

  backend = gum_script_backend_obtain_qjs();

  context = gum_script_scheduler_get_js_context(scheduler);
  main_loop = g_main_loop_new(context, true);
  g_main_context_push_thread_default(context);

  gum_script_backend_create(backend, "example", source, cancellable, create_cb,
                            &error);

  while (g_main_context_pending(context))
    g_main_context_iteration(context, FALSE);

  if (!js_done) { FFATAL("Script didn't call Afl.done()"); }

}

gboolean js_stalker_callback(const cs_insn *insn, gboolean begin,
                             gboolean excluded, GumStalkerOutput *output) {

  if (js_user_callback == NULL) { return TRUE; }
  return js_user_callback(insn, begin, excluded, output);

}

