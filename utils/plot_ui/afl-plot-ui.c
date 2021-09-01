#include <gtk/gtk.h>
#include <gtk/gtkx.h>
#include <stdio.h>
#include <string.h>

char USAGE[] =
    "is a helper utility for rendering the GNUplot graphs in a GTK window. This allows to real time resizing, scrolling, and cursor positioning features while viewing the graph. This utility also provides options to hide graphs using check buttons.\n \
\n \
Usage:\n \
    -h, --help      Show this help menu\n \
\n \
NOTE: This utility is not meant to be used standalone. Never run this utility directly. Always run afl-plot, which will, in turn, invoke this utility (when run using `-g` or `--graphical` flag).\n \
";

static void plot_toggled(GtkWidget *caller, gpointer data);

int main(int argc, char **argv) {

  if (argc == 2 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "-help"))) {

    printf("%s %s", argv[0], USAGE);
    return EXIT_SUCCESS;

  }

  GtkWidget *window;
  GtkWidget *main_vbox;

  GtkWidget *cbuttons_frame;
  GtkWidget *cbuttons_hbox;

  GtkWidget *separator_top;
  GtkWidget *pane1, *pane2, *pane3;

  GtkWidget *plots_vbox;
  GtkWidget *plot_edges_frame, *plot_exec_speed_frame, *plot_high_freq_frame,
      *plot_low_freq_frame;
  GtkWidget *plot_edges, *plot_exec_speed, *plot_high_freq, *plot_low_freq;

  gtk_init(&argc, &argv);

  window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
  gtk_window_set_title(GTK_WINDOW(window), "Graph drawing");
  gtk_container_set_border_width(GTK_CONTAINER(window), 10);

  main_vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);

  cbuttons_frame = gtk_frame_new("Select the plots");
  gtk_container_set_border_width(GTK_CONTAINER(cbuttons_frame), 5);

  cbuttons_hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 1);

  GtkWidget *cbutton_edges, *cbutton_exec_speed, *cbutton_high_freq,
      *cbutton_low_freq;

  cbutton_edges = gtk_check_button_new_with_label("Edges");
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(cbutton_edges), TRUE);
  g_signal_connect(cbutton_edges, "toggled", G_CALLBACK(plot_toggled),
                   &plot_edges_frame);

  cbutton_exec_speed = gtk_check_button_new_with_label("Execution Speed");
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(cbutton_exec_speed), TRUE);
  g_signal_connect(cbutton_exec_speed, "toggled", G_CALLBACK(plot_toggled),
                   &plot_exec_speed_frame);

  cbutton_high_freq = gtk_check_button_new_with_label("High Frequency");
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(cbutton_high_freq), TRUE);
  g_signal_connect(cbutton_high_freq, "toggled", G_CALLBACK(plot_toggled),
                   &plot_high_freq_frame);

  cbutton_low_freq = gtk_check_button_new_with_label("Low Frequency");
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(cbutton_low_freq), TRUE);
  g_signal_connect(cbutton_low_freq, "toggled", G_CALLBACK(plot_toggled),
                   &plot_low_freq_frame);

  gtk_box_pack_start(GTK_BOX(cbuttons_hbox), cbutton_edges, TRUE, TRUE, 1);
  gtk_box_pack_start(GTK_BOX(cbuttons_hbox), cbutton_exec_speed, TRUE, TRUE, 1);
  gtk_box_pack_start(GTK_BOX(cbuttons_hbox), cbutton_high_freq, TRUE, TRUE, 1);
  gtk_box_pack_start(GTK_BOX(cbuttons_hbox), cbutton_low_freq, TRUE, TRUE, 1);

  gtk_container_add(GTK_CONTAINER(cbuttons_frame), cbuttons_hbox);
  gtk_box_pack_start(GTK_BOX(main_vbox), cbuttons_frame, FALSE, TRUE, 1);

  separator_top = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);
  gtk_box_pack_start(GTK_BOX(main_vbox), separator_top, FALSE, TRUE, 1);

  plots_vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);

  plot_edges_frame = gtk_frame_new("Edges");
  gtk_frame_set_shadow_type(GTK_FRAME(plot_edges_frame), GTK_SHADOW_IN);
  gtk_container_set_border_width(GTK_CONTAINER(plot_edges_frame), 10);
  plot_edges = gtk_socket_new();
  gtk_widget_set_size_request(plot_edges, -1, 100);
  gtk_container_add(GTK_CONTAINER(plot_edges_frame), plot_edges);

  plot_exec_speed_frame = gtk_frame_new("Exec Speed");
  gtk_frame_set_shadow_type(GTK_FRAME(plot_exec_speed_frame), GTK_SHADOW_IN);
  gtk_container_set_border_width(GTK_CONTAINER(plot_exec_speed_frame), 10);
  plot_exec_speed = gtk_socket_new();
  gtk_widget_set_size_request(plot_exec_speed, -1, 100);
  gtk_container_add(GTK_CONTAINER(plot_exec_speed_frame), plot_exec_speed);

  plot_high_freq_frame = gtk_frame_new("High Frequency");
  gtk_frame_set_shadow_type(GTK_FRAME(plot_high_freq_frame), GTK_SHADOW_IN);
  gtk_container_set_border_width(GTK_CONTAINER(plot_high_freq_frame), 10);
  plot_high_freq = gtk_socket_new();
  gtk_widget_set_size_request(plot_high_freq, -1, 100);
  gtk_container_add(GTK_CONTAINER(plot_high_freq_frame), plot_high_freq);

  plot_low_freq_frame = gtk_frame_new("Low Frequency");
  gtk_frame_set_shadow_type(GTK_FRAME(plot_low_freq_frame), GTK_SHADOW_IN);
  gtk_container_set_border_width(GTK_CONTAINER(plot_low_freq_frame), 10);
  plot_low_freq = gtk_socket_new();
  gtk_widget_set_size_request(plot_low_freq, -1, 100);
  gtk_container_add(GTK_CONTAINER(plot_low_freq_frame), plot_low_freq);

  pane1 = gtk_paned_new(GTK_ORIENTATION_VERTICAL);
  pane2 = gtk_paned_new(GTK_ORIENTATION_VERTICAL);
  pane3 = gtk_paned_new(GTK_ORIENTATION_VERTICAL);

  gtk_paned_pack1(GTK_PANED(pane1), plot_edges_frame, TRUE, FALSE);
  gtk_paned_pack2(GTK_PANED(pane1), plot_exec_speed_frame, TRUE, FALSE);

  gtk_paned_pack1(GTK_PANED(pane2), pane1, TRUE, FALSE);
  gtk_paned_pack2(GTK_PANED(pane2), plot_high_freq_frame, TRUE, FALSE);

  gtk_paned_pack1(GTK_PANED(pane3), pane2, TRUE, FALSE);
  gtk_paned_pack2(GTK_PANED(pane3), plot_low_freq_frame, TRUE, FALSE);

  gtk_box_pack_start(GTK_BOX(plots_vbox), pane3, TRUE, TRUE, 0);

  gtk_box_pack_start(GTK_BOX(main_vbox), plots_vbox, TRUE, TRUE, 1);

  gtk_container_add(GTK_CONTAINER(window), main_vbox);

  guint id_edges = gtk_socket_get_id(GTK_SOCKET(plot_edges));
  guint id_exec_speed = gtk_socket_get_id(GTK_SOCKET(plot_exec_speed));
  guint id_high_freq = gtk_socket_get_id(GTK_SOCKET(plot_high_freq));
  guint id_low_freq = gtk_socket_get_id(GTK_SOCKET(plot_low_freq));

  printf("%x\n%x\n%x\n%x\n", id_edges, id_exec_speed, id_high_freq,
         id_low_freq);

  fclose(stdout);

  g_signal_connect(G_OBJECT(window), "destroy", G_CALLBACK(gtk_main_quit),
                   NULL);
  gtk_widget_show_all(window);
  gtk_window_maximize(GTK_WINDOW(window));
  gtk_main();

  return EXIT_SUCCESS;

}

static void plot_toggled(GtkWidget *caller, gpointer data) {

  gboolean state = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(caller));

  GtkWidget *widget = *(GtkWidget **)data;

  if (state) {

    gtk_widget_show(widget);

  } else {

    gtk_widget_hide(widget);

  }

}

