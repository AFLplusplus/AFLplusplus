#include <gtk/gtk.h>
#include <gtk/gtkx.h>
#include <stdio.h>

#define WIDTH 400
#define HEIGHT 640

static void plot_toggled(GtkWidget *caller, gpointer data);

int main(int argc, char **argv) {

  GtkWidget *window;
  GtkWidget *main_vbox;

  GtkWidget *cbuttons_frame;
  GtkWidget *cbuttons_hbox;

  GtkWidget *separator_maj, *separator_min1, *separator_min2, *separator_min3;

  GtkWidget *plots_vbox;
  GtkWidget *plot_edges_frame, *plot_exec_speed_frame, *plot_high_freq_frame,
      *plot_low_freq_frame;
  GtkWidget *plot_edges, *plot_exec_speed, *plot_high_freq, *plot_low_freq;

  gtk_init(&argc, &argv);

  window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
  gtk_window_set_default_size(GTK_WINDOW(window), WIDTH, HEIGHT);
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

  separator_maj = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);
  gtk_box_pack_start(GTK_BOX(main_vbox), separator_maj, FALSE, TRUE, 1);

  plots_vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);

  plot_edges_frame = gtk_frame_new("Edges");
  gtk_container_set_border_width(GTK_CONTAINER(plot_edges_frame), 5);
  plot_edges = gtk_socket_new();
  gtk_container_add(GTK_CONTAINER(plot_edges_frame), plot_edges);

  plot_exec_speed_frame = gtk_frame_new("Exec Speed");
  gtk_container_set_border_width(GTK_CONTAINER(plot_exec_speed_frame), 5);
  plot_exec_speed = gtk_socket_new();
  gtk_container_add(GTK_CONTAINER(plot_exec_speed_frame), plot_exec_speed);

  plot_high_freq_frame = gtk_frame_new("High Frequency");
  gtk_container_set_border_width(GTK_CONTAINER(plot_high_freq_frame), 5);
  plot_high_freq = gtk_socket_new();
  gtk_container_add(GTK_CONTAINER(plot_high_freq_frame), plot_high_freq);

  plot_low_freq_frame = gtk_frame_new("Low Frequency");
  gtk_container_set_border_width(GTK_CONTAINER(plot_low_freq_frame), 5);
  plot_low_freq = gtk_socket_new();
  gtk_container_add(GTK_CONTAINER(plot_low_freq_frame), plot_low_freq);

  separator_min1 = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);
  separator_min2 = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);
  separator_min3 = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);

  gtk_box_pack_start(GTK_BOX(plots_vbox), plot_edges_frame, TRUE, TRUE, 1);
  gtk_box_pack_start(GTK_BOX(plots_vbox), separator_min1, FALSE, TRUE, 1);

  gtk_box_pack_start(GTK_BOX(plots_vbox), plot_exec_speed_frame, TRUE, TRUE, 1);
  gtk_box_pack_start(GTK_BOX(plots_vbox), separator_min2, FALSE, TRUE, 1);

  gtk_box_pack_start(GTK_BOX(plots_vbox), plot_high_freq_frame, TRUE, TRUE, 1);
  gtk_box_pack_start(GTK_BOX(plots_vbox), separator_min3, FALSE, TRUE, 1);

  gtk_box_pack_start(GTK_BOX(plots_vbox), plot_low_freq_frame, TRUE, TRUE, 1);

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
