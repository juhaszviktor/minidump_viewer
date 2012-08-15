#include "minidump.h"
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <glib.h>
#include <stdio.h>
#include <unistd.h>

static void *
mini_dump_translate_rva(MiniDump *self, guint32 rva)
{
  return (void *)((guint8 *)self->base + rva);
}

static void
mini_dump_map_dir(MiniDump *self)
{
  guint32 i = 0;
  self->directories = mini_dump_translate_rva(self,self->header->StreamDirectoryRva);
  for (i = 0; i < self->header->NumberOfStreams; i++)
    {
      MINIDUMP_DIRECTORY *dir = &self->directories[i];
      switch (dir->StreamType)
        {
          case ThreadListStream:
              self->thread_list = mini_dump_translate_rva(self,dir->Location.Rva);
              break;
          case ModuleListStream:
              self->module_list = mini_dump_translate_rva(self,dir->Location.Rva);
              break;
          case MemoryListStream:
              self->memory_list = mini_dump_translate_rva(self,dir->Location.Rva);
              break;
          case ExceptionStream:
              self->exception_stream = mini_dump_translate_rva(self,dir->Location.Rva);
              break;
          case SystemInfoStream:
              self->system_info = mini_dump_translate_rva(self,dir->Location.Rva);
              break;
          case Memory64ListStream:
              self->memory64_list = mini_dump_translate_rva(self,dir->Location.Rva);
              break;
          default:
            break;
        } 
    }
}

static void
mini_dump_set_base(MiniDump *self, void *base)
{
  self->base = base;
  self->header = base;
}

MiniDump *
mini_dump_new(gchar *filename)
{
  MiniDump *self = g_new0(MiniDump,1);
  self->filename = g_string_new(filename);
  self->fd = -1;
  mini_dump_set_base(self, MAP_FAILED);
  return self;
}

gboolean
mini_dump_open(MiniDump *self)
{
  struct stat sb;
  void *map;
  self->fd = open(self->filename->str, O_RDONLY);
  if (self->fd == -1)
    {
      fprintf(stderr, "Can't open file: %s\n",self->filename->str);
      return FALSE;
    }
  if (fstat(self->fd, &sb) == -1)
    {
      fprintf(stderr, "Can't stats file\n");
      mini_dump_close(self);
      return FALSE;
    }
  self->size = sb.st_size;
  map = mmap(NULL,sb.st_size,PROT_READ,MAP_SHARED,self->fd,0);
  if (map == MAP_FAILED)
    {
      fprintf(stderr, "Can't map the file\n");
      mini_dump_close(self);
      return FALSE;
    }
  mini_dump_set_base(self, map);
  if (self->header->Signature != 0x504d444d)
    {
      mini_dump_close(self);
      return FALSE;
    }
  mini_dump_map_dir(self);
  
  return TRUE;
}

void
mini_dump_close(MiniDump *self)
{
  if (self->base != MAP_FAILED && self->size != 0)
    {
      munmap(self->base, self->size);
      mini_dump_set_base(self, MAP_FAILED);
    }
  if (self->fd != -1)
    {
      close(self->fd);
      self->fd = -1;
    }
}

void
mini_dump_free(MiniDump *self)
{
  mini_dump_close(self);
  g_string_free(self->filename, TRUE);
  g_free(self);
}
