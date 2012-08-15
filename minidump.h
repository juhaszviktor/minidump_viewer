#ifndef _MINIDUMP_H
#define _MINIDUMP_H 1

#include <glib.h>

typedef enum _MINIDUMP_TYPE { 
  MiniDumpNormal                           = 0x00000000,
  MiniDumpWithDataSegs                     = 0x00000001,
  MiniDumpWithFullMemory                   = 0x00000002,
  MiniDumpWithHandleData                   = 0x00000004,
  MiniDumpFilterMemory                     = 0x00000008,
  MiniDumpScanMemory                       = 0x00000010,
  MiniDumpWithUnloadedModules              = 0x00000020,
  MiniDumpWithIndirectlyReferencedMemory   = 0x00000040,
  MiniDumpFilterModulePaths                = 0x00000080,
  MiniDumpWithProcessThreadData            = 0x00000100,
  MiniDumpWithPrivateReadWriteMemory       = 0x00000200,
  MiniDumpWithoutOptionalData              = 0x00000400,
  MiniDumpWithFullMemoryInfo               = 0x00000800,
  MiniDumpWithThreadInfo                   = 0x00001000,
  MiniDumpWithCodeSegs                     = 0x00002000,
  MiniDumpWithoutAuxiliaryState            = 0x00004000,
  MiniDumpWithFullAuxiliaryState           = 0x00008000,
  MiniDumpWithPrivateWriteCopyMemory       = 0x00010000,
  MiniDumpIgnoreInaccessibleMemory         = 0x00020000,
  MiniDumpWithTokenInformation             = 0x00040000 
} MINIDUMP_TYPE;

typedef enum _MINIDUMP_STREAM_TYPE { 
  UnusedStream                = 0,
  ReservedStream0             = 1,
  ReservedStream1             = 2,
  ThreadListStream            = 3,
  ModuleListStream            = 4,
  MemoryListStream            = 5,
  ExceptionStream             = 6,
  SystemInfoStream            = 7,
  ThreadExListStream          = 8,
  Memory64ListStream          = 9,
  CommentStreamA              = 10,
  CommentStreamW              = 11,
  HandleDataStream            = 12,
  FunctionTableStream         = 13,
  UnloadedModuleListStream    = 14,
  MiscInfoStream              = 15,
  MemoryInfoListStream        = 16,
  ThreadInfoListStream        = 17,
  HandleOperationListStream   = 18,
  LastReservedStream          = 0xffff 
} MINIDUMP_STREAM_TYPE;

#define EXCEPTION_MAXIMUM_PARAMETERS 15

typedef struct _MINIDUMP_LOCATION_DESCRIPTOR {
  guint32 DataSize;
  guint32 Rva;
} MINIDUMP_LOCATION_DESCRIPTOR;

typedef struct _MINIDUMP_DIRECTORY {
  guint32 StreamType;
  MINIDUMP_LOCATION_DESCRIPTOR Location;
} MINIDUMP_DIRECTORY, *PMINIDUMP_DIRECTORY;

typedef struct _MINIDUMP_MEMORY_DESCRIPTOR {
  guint64                      StartOfMemoryRange;
  MINIDUMP_LOCATION_DESCRIPTOR Memory;
} MINIDUMP_MEMORY_DESCRIPTOR, *PMINIDUMP_MEMORY_DESCRIPTOR;

typedef struct _MINIDUMP_MEMORY_DESCRIPTOR64 {
    guint64 StartOfMemoryRange;
    guint64 DataSize;
} MINIDUMP_MEMORY_DESCRIPTOR64, *PMINIDUMP_MEMORY_DESCRIPTOR64;

typedef struct _MINIDUMP_THREAD {
  guint32                      ThreadId;
  guint32                      SuspendCount;
  guint32                      PriorityClass;
  guint32                      Priority;
  guint64                      Teb;
  MINIDUMP_MEMORY_DESCRIPTOR   Stack;
  MINIDUMP_LOCATION_DESCRIPTOR ThreadContext;
} MINIDUMP_THREAD, *PMINIDUMP_THREAD;

typedef struct _MINIDUMP_THREAD_LIST {
  guint32         NumberOfThreads;
  MINIDUMP_THREAD Threads[];
} MINIDUMP_THREAD_LIST, *PMINIDUMP_THREAD_LIST;

typedef struct tagVS_FIXEDFILEINFO {
  guint32 dwSignature;
  guint32 dwStrucVersion;
  guint32 dwFileVersionMS;
  guint32 dwFileVersionLS;
  guint32 dwProductVersionMS;
  guint32 dwProductVersionLS;
  guint32 dwFileFlagsMask;
  guint32 dwFileFlags;
  guint32 dwFileOS;
  guint32 dwFileType;
  guint32 dwFileSubtype;
  guint32 dwFileDateMS;
  guint32 dwFileDateLS;
} VS_FIXEDFILEINFO;

typedef struct _MINIDUMP_STRING {
  guint32 Length;
  short    Buffer[];
} MINIDUMP_STRING, *PMINIDUMP_STRING;

typedef struct _MINIDUMP_MEMORY_LIST {
  guint32                    NumberOfMemoryRanges;
  MINIDUMP_MEMORY_DESCRIPTOR MemoryRanges[];
} MINIDUMP_MEMORY_LIST, *PMINIDUMP_MEMORY_LIST;

typedef struct _MINIDUMP_MEMORY64_LIST {
    guint64 NumberOfMemoryRanges;
    guint64 BaseRva;
    MINIDUMP_MEMORY_DESCRIPTOR64 MemoryRanges [0];
} MINIDUMP_MEMORY64_LIST, *PMINIDUMP_MEMORY64_LIST;

typedef struct _MINIDUMP_SYSTEM_INFO {
  guint16  ProcessorArchitecture;
  guint16  ProcessorLevel;
  guint16  ProcessorRevision;
  union {
    guint16 Reserved0;
    struct {
      guint8 NumberOfProcessors;
      guint8 ProductType;
    };
  };
  guint32 MajorVersion;
  guint32 MinorVersion;
  guint32 BuildNumber;
  guint32 PlatformId;
  guint32     CSDVersionRva;
  union {
    guint32 Reserved1;
    struct {
      guint16 SuiteMask;
      guint16 Reserved2;
    };
  };
  union {
    struct {
      guint32 VendorId[3];
      guint32 VersionInformation;
      guint32 FeatureInformation;
      guint32 AMDExtendedCpuFeatures;
    } X86CpuInfo;
    struct {
      guint64 ProcessorFeatures[2];
    } OtherCpuInfo;
  } Cpu;
} MINIDUMP_SYSTEM_INFO, *PMINIDUMP_SYSTEM_INFO;

typedef struct _MINIDUMP_THREAD_EX {
  guint32                      ThreadId;
  guint32                      SuspendCount;
  guint32                      PriorityClass;
  guint32                      Priority;
  guint64                      Teb;
  MINIDUMP_MEMORY_DESCRIPTOR   Stack;
  MINIDUMP_LOCATION_DESCRIPTOR ThreadContext;
  MINIDUMP_MEMORY_DESCRIPTOR   BackingStore;
} MINIDUMP_THREAD_EX, *PMINIDUMP_THREAD_EX;

typedef struct _MINIDUMP_THREAD_EX_LIST {
  guint32            NumberOfThreads;
  MINIDUMP_THREAD_EX Threads[];
} MINIDUMP_THREAD_EX_LIST, *PMINIDUMP_THREAD_EX_LIST;

typedef struct _MINIDUMP_EXCEPTION {
  guint32 ExceptionCode;
  guint32 ExceptionFlags;
  guint64 ExceptionRecord;
  guint64 ExceptionAddress;
  guint32 NumberParameters;
  guint32 __unusedAlignment;
  guint64 ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
} MINIDUMP_EXCEPTION, *PMINIDUMP_EXCEPTION;

typedef struct MINIDUMP_EXCEPTION_STREAM {
  guint32                      ThreadId;
  guint32                      __alignment;
  MINIDUMP_EXCEPTION           ExceptionRecord;
  MINIDUMP_LOCATION_DESCRIPTOR ThreadContext;
} MINIDUMP_EXCEPTION_STREAM, *PMINIDUMP_EXCEPTION_STREAM;

typedef struct _MINIDUMP_MODULE {
  guint64                      BaseOfImage;
  guint32                      SizeOfImage;
  guint32                      CheckSum;
  guint32                      TimeDateStamp;
  guint32                          ModuleNameRva;
  VS_FIXEDFILEINFO             VersionInfo;
  MINIDUMP_LOCATION_DESCRIPTOR CvRecord;
  MINIDUMP_LOCATION_DESCRIPTOR MiscRecord;
  guint64                      Reserved0;
  guint64                      Reserved1;
} MINIDUMP_MODULE, *PMINIDUMP_MODULE;

typedef struct _MINIDUMP_MODULE_LIST {
  guint32         NumberOfModules;
  MINIDUMP_MODULE Modules[];
} MINIDUMP_MODULE_LIST, *PMINIDUMP_MODULE_LIST;

typedef struct _MINIDUMP_HEADER {
  guint32 Signature;
  guint32 Version;
  guint32 NumberOfStreams;
  guint32 StreamDirectoryRva;
  guint32 CheckSum;
  union {
    guint32 Reserved;
    guint32 TimeDateStamp;
  };
  guint64 Flags;
} MINIDUMP_HEADER, *PMINIDUMP_HEADER;

typedef struct _MiniDump MiniDump;

MiniDump *mini_dump_new(gchar *filename);
gboolean mini_dump_open(MiniDump *self);
void mini_dump_close(MiniDump *self);
void mini_dump_free(MiniDump *self);
#endif
