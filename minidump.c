#include "minidump.h"
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <glib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <bfd.h>

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

gchar *
mini_dump_get_module_name_by_address(MiniDump *self,guint64 address)
{
  guint32 i = 0;
  gchar *result = NULL;
  while(i < self->module_list->NumberOfModules)
    {
      MINIDUMP_MODULE *module = &self->module_list->Modules[i];
      if ((address > module->BaseOfImage) && (address < (module->BaseOfImage + module->SizeOfImage)))
        {
          guint32 rva = module->ModuleNameRva;
          MINIDUMP_STRING *name = mini_dump_translate_rva(self,rva);
          result = g_utf16_to_utf8(name->Buffer, name->Length, NULL, NULL, NULL);
          break;
        }
      i++;
    }
  return result;
}

void *
mini_dump_get_memory_pointer(MiniDump *self,guint64 address)
{
  void *result = NULL;
  if (self->memory64_list)
    {
      guint64 rva = self->memory64_list->BaseRva;
      guint32 i = 0;
      while(i < self->memory64_list->NumberOfMemoryRanges)
        {
          if (address > self->memory64_list->MemoryRanges[i].StartOfMemoryRange && 
              address < self->memory64_list->MemoryRanges[i].StartOfMemoryRange + self->memory64_list->MemoryRanges[i].DataSize)
            {
              result = mini_dump_translate_rva(self,rva + (address - self->memory64_list->MemoryRanges[i].StartOfMemoryRange));
              break;
            }
          rva += self->memory64_list->MemoryRanges[i].DataSize; 
          i++;
        }
    }
  else if (self->memory_list)
    {
      guint32 i = 0;
      while (i < self->memory_list->NumberOfMemoryRanges)
        {
          MINIDUMP_MEMORY_DESCRIPTOR *mem = &self->memory_list->MemoryRanges[i];
          if ((address > mem->StartOfMemoryRange) && (address < (mem->StartOfMemoryRange + mem->Memory.DataSize)))
            {
              result = mini_dump_translate_rva(self, mem->Memory.Rva + (address - mem->StartOfMemoryRange));
            }
          i++;
        } 
    }
  return result;
}

static void
mini_dump_set_base(MiniDump *self, void *base)
{
  self->base = base;
  self->header = base;
}

MiniDump *
mini_dump_new(gchar *filename, gchar *binary_directory)
{
  MiniDump *self = g_malloc0(sizeof(MiniDump));
  self->filename = g_string_new(filename);
  self->bin_dir = binary_directory;
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

void
mini_dump_get_debug_info_about_address(MiniDump *self, guint64 address, gchar *module_name, const gchar **source_file_name, const gchar **function_name,guint *line_number)
{
  gchar *filename = g_build_filename(self->bin_dir,module_name, NULL);
  bfd *abfd = bfd_openr(filename,NULL);
  asection *section;
  long storage;
  long symcount;
  bfd_boolean dynamic = FALSE;
  asymbol **syms;  
  if (abfd == NULL)
    return;
  if (!bfd_check_format (abfd, bfd_object))
    {
      bfd_close(abfd);
      return; 
    }
  if ((bfd_get_file_flags (abfd) & HAS_SYMS) == 0)
    {
      bfd_close(abfd);
      return;
    }
  storage = bfd_get_symtab_upper_bound (abfd);
  if (storage == 0)
    {
      storage = bfd_get_dynamic_symtab_upper_bound (abfd);
      dynamic = TRUE;
    }
  if (storage < 0)
    {
      bfd_close(abfd);
      return;
    }
  syms = (asymbol **) g_malloc0(storage);
  if (dynamic)
    symcount = bfd_canonicalize_dynamic_symtab (abfd, syms);
  else
    symcount = bfd_canonicalize_symtab (abfd, syms);
  if (symcount < 0)
    {
      bfd_close(abfd);
      g_free(syms);
      return;
    }
  section = abfd->sections;
  while(section)
    {
      bfd_vma vma;
      bfd_vma pc = address;
      bfd_size_type size;
      if ((bfd_get_section_flags (abfd, section) & SEC_ALLOC) == 0)
        {
          goto next_iteration;
        }
      vma = bfd_get_section_vma (abfd, section);
      if (pc < vma)
        {
          goto next_iteration;
        }
      size = bfd_get_section_size (section);
      if (pc >= vma + size)
        {
          goto next_iteration;
        }
      if (bfd_find_nearest_line (abfd, section, syms, pc - vma, source_file_name, function_name, line_number))
        {
          break;
        }
next_iteration:
      section = section->next;
    } 
}

void
mini_dump_print_thread_32_backtrace(MiniDump *self,MINIDUMP_LOCATION_DESCRIPTOR *thread_context)
{
  CONTEXT_X86_32 *context = mini_dump_translate_rva(self,thread_context->Rva);
  fprintf(stderr,"THREAD REGISTERS:\nEIP = %08X;EAX = %08X; EBX = %08X; ECX = %08X; EDX = %08X; EBP = %08X; ESP = %08X; EDI = %08X\n",
          context->Eip, context->Eax, context->Ebx, context->Ecx, context->Edx, context->Ebp, context->Esp, context->Edi);
      
  fprintf(stderr,"Address\tModuleName\n");
  guint64 address = context->Eip;
  guint32 *frame = mini_dump_get_memory_pointer(self, context->Ebp);
  while (frame)
    {
      gchar *name = mini_dump_get_module_name_by_address(self, address);
      gchar *p;
      const gchar *source_file_name = NULL;
      const gchar *function_name = NULL;
      guint line_number = 0;
      if (name)
        {
          p = strrchr(name,'\\');
          if (p)
            {
              p++; 
            }
          else
            {
              p = name;
            }
          if (self->bin_dir)
            {
              mini_dump_get_debug_info_about_address(self,address,p,&source_file_name,&function_name,&line_number);
            }
        }
      else
        {
          p = "??";
        }
      if (source_file_name)
        {
          fprintf(stderr,"%08X\t%s\t%s(%d):%s\n",address,p,source_file_name,line_number,function_name);
        }
      else
        {
          fprintf(stderr,"%08X\t%s\n",address,p);
        }
      g_free(name);
      address = frame[1];
      frame = mini_dump_get_memory_pointer(self, frame[0]);
    }
}

void
mini_dump_print_thread_64_backtrace(MiniDump *self, MINIDUMP_LOCATION_DESCRIPTOR *thread_context)
{
  CONTEXT_X86_64 *context = mini_dump_translate_rva(self,thread_context->Rva);
  fprintf(stderr,"THREAD REGISTERS:\nRIP = %08X;RAX = %08X; RBX = %08X; RCX = %08X; RDX = %08X; RBP = %08X; RSP = %08X; RDI = %08X\n",
          context->Rip, context->Rax, context->Rbx, context->Rcx, context->Rdx, context->Rbp, context->Rsp, context->Rdi);
      
  fprintf(stderr,"Address\tModuleName\n");
  guint64 address = context->Rip;
  guint64 *frame = mini_dump_get_memory_pointer(self, context->Rbp);
  while (frame)
    {
      gchar *name = mini_dump_get_module_name_by_address(self, address);
      gchar *p;
      if (name)
        {
          p = strrchr(name,'\\');
          if (p)
            {
              p++; 
            }
          else
            {
              p = name;
            }
        }
      else
        {
          p = "??";
        }
      fprintf(stderr,"%08X\t%s\n",address,p);
      g_free(name);
      address = frame[1];
      frame = mini_dump_get_memory_pointer(self, frame[0]);
    }
}

void
mini_dump_print_thread_backtrace(MiniDump *self, MINIDUMP_LOCATION_DESCRIPTOR *thread_context)
{
  if (self->system_info->ProcessorArchitecture == 9)
    mini_dump_print_thread_64_backtrace(self,thread_context);
  else if (self->system_info->ProcessorArchitecture == 0)
    mini_dump_print_thread_32_backtrace(self,thread_context);
  else
    fprintf(stderr,"INVALID PROCESS TYPE: %d\n",self->system_info->ProcessorArchitecture);
}

void
mini_dump_print_stackwalk(MiniDump *self)
{
  fprintf(stderr,"EXCEPTION INFO: \n");
  fprintf(stderr,"\tTHREAD ID: %d\n",self->exception_stream->ThreadId);
  fprintf(stderr,"\tEXCEPTION CODE: %08X\n",self->exception_stream->ExceptionRecord.ExceptionCode);
  fprintf(stderr,"\tEXCEPTION ADDRESS: %08X\n",self->exception_stream->ExceptionRecord.ExceptionAddress);
  fprintf(stderr,"\nEXCEPTION BACKTRACE:\n");
  mini_dump_print_thread_backtrace(self, &self->exception_stream->ThreadContext);
  guint32 i = 0;
  for (i = 0; i < self->thread_list->NumberOfThreads; i++)
    {
      MINIDUMP_THREAD *thread  = &self->thread_list->Threads[i];
      fprintf(stderr,"\nThread(%d) backtrace:\n",thread->ThreadId);
      mini_dump_print_thread_backtrace(self,&thread->ThreadContext);
    }
}
