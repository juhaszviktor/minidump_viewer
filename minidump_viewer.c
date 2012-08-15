#include <stdio.h>
#include <sys/mman.h>
#include <glib.h>
#include "minidump.h"

static gchar *minidump_filename = NULL;
static gchar *binary_path;

static GOptionEntry options[] =
{
  { "binary_path", 'b', 0, G_OPTION_ARG_STRING, &binary_path, "Path of the binaries to resolve addresses to symbol", NULL },
  { NULL }
};

int main(int argc,char **argv)
{
  GError *error = NULL;
  GOptionContext *context;
  MiniDump *md;
  context = g_option_context_new ("minidumpfile");
  g_option_context_add_main_entries (context, options, NULL);
  if (!g_option_context_parse (context, &argc, &argv, &error))
    {
      g_print ("option parsing failed: %s\n", error->message);
      return 1;
    }
  if (argc != 2)
    {
      g_print ("Minidumpfile is required!\n");
      g_print ("%s\n", g_option_context_get_help(context,TRUE,NULL));
      return 0;
    }
  minidump_filename = argv[1];
  md = mini_dump_new(minidump_filename);
  if (mini_dump_open(md))
    {
      fprintf(stderr,"YESSSSSSSSSSSS!\n");
      //fprintf(stderr,"0x%02x%02X\n",md->system_info->MajorVersion,md->system_info->MinorVersion);
    } 
  mini_dump_free(md);
  return 0;
}
