#ifndef _MINIDUMP_H
#define _MINIDUMP_H 1

#include <glib.h>
#pragma pack(1)

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
  guint16 Buffer[];
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

struct _MiniDump {
  int fd;
  guint64 size;
  void *base;
  GString *filename;
  gchar *bin_dir;

  MINIDUMP_HEADER *header;
  MINIDUMP_DIRECTORY *directories;
  MINIDUMP_THREAD_LIST *thread_list;
  MINIDUMP_EXCEPTION_STREAM *exception_stream;
  MINIDUMP_MODULE_LIST *module_list;
  MINIDUMP_MEMORY_LIST *memory_list;
  MINIDUMP_MEMORY64_LIST *memory64_list;
  MINIDUMP_SYSTEM_INFO *system_info;
};

#define MAXIMUM_SUPPORTED_EXTENSION 512 
#define DECLSPEC_ALIGN(n) __declspec(align(n))

typedef struct _FLOATING_SAVE_AREA {
  guint32 ControlWord;
  guint32 StatusWord;
  guint32 TagWord;
  guint32 ErrorOffset;
  guint32 ErrorSelector;
  guint32 DataOffset;
  guint32 DataSelector;
  guint8  RegisterArea[80];
  guint32 Cr0NpxState;
} FLOATING_SAVE_AREA; 

typedef struct _CONTEXT_X86_32 {
  guint32 ContextFlags;
  guint32 Dr0;
  guint32 Dr1;
  guint32 Dr2;
  guint32 Dr3;
  guint32 Dr6;
  guint32 Dr7;
  FLOATING_SAVE_AREA FloatSave;
  guint32 SegGs;
  guint32 SegFs;
  guint32 SegEs;
  guint32 SegDs;
  guint32 Edi;
  guint32 Esi;
  guint32 Ebx;
  guint32 Edx;
  guint32 Ecx;
  guint32 Eax;
  guint32 Ebp;
  guint32 Eip;
  guint32 SegCs;
  guint32 EFlags;
  guint32 Esp;
  guint32 SegSs;
  guint8  ExtendedRegisters[MAXIMUM_SUPPORTED_EXTENSION];
} CONTEXT_X86_32;


typedef struct _M128A {
    guint64 Low;
    gint64 High;
} M128A,*PM128A;

typedef struct _XMM_SAVE_AREA32 {
    guint16 ControlWord;
    guint16 StatusWord;
    guint8 TagWord;
    guint8 Reserved1;
    guint16 ErrorOpcode;
    guint32 ErrorOffset;
    guint16 ErrorSelector;
    guint16 Reserved2;
    guint32 DataOffset;
    guint16 DataSelector;
    guint16 Reserved3;
    guint32 MxCsr;
    guint32 MxCsr_Mask;
    M128A FloatRegisters[8];
    M128A XmmRegisters[16];
    guint8 Reserved4[96];
} XMM_SAVE_AREA32,*PXMM_SAVE_AREA32;

#define LEGACY_SAVE_AREA_LENGTH sizeof(XMM_SAVE_AREA32)

typedef struct _CONTEXT_X86_64 {
    guint64 P1Home;
    guint64 P2Home;
    guint64 P3Home;
    guint64 P4Home;
    guint64 P5Home;
    guint64 P6Home;
    guint32 ContextFlags;
    guint32 MxCsr;
    guint16 SegCs;
    guint16 SegDs;
    guint16 SegEs;
    guint16 SegFs;
    guint16 SegGs;
    guint16 SegSs;
    guint32 EFlags;
    guint64 Dr0;
    guint64 Dr1;
    guint64 Dr2;
    guint64 Dr3;
    guint64 Dr6;
    guint64 Dr7;
    guint64 Rax;
    guint64 Rcx;
    guint64 Rdx;
    guint64 Rbx;
    guint64 Rsp;
    guint64 Rbp;
    guint64 Rsi;
    guint64 Rdi;
    guint64 R8;
    guint64 R9;
    guint64 R10;
    guint64 R11;
    guint64 R12;
    guint64 R13;
    guint64 R14;
    guint64 R15;
    guint64 Rip;
    union 
      {
        XMM_SAVE_AREA32 FltSave;
        XMM_SAVE_AREA32 FloatSave;
        struct
          {
            M128A Header[2];
            M128A Legacy[8];
            M128A Xmm0;
            M128A Xmm1;
            M128A Xmm2;
            M128A Xmm3;
            M128A Xmm4;
            M128A Xmm5;
            M128A Xmm6;
            M128A Xmm7;
            M128A Xmm8;
            M128A Xmm9;
            M128A Xmm10;
            M128A Xmm11;
            M128A Xmm12;
            M128A Xmm13;
            M128A Xmm14;
            M128A Xmm15;
          };
      };
    M128A VectorRegister[26];
    guint64 VectorControl;
    guint64 DebugControl;
    guint64 LastBranchToRip;
    guint64 LastBranchFromRip;
    guint64 LastExceptionToRip;
    guint64 LastExceptionFromRip;
  } CONTEXT_X86_64,*PCONTEXT_X86_64; 

typedef struct _MiniDump MiniDump;

#pragma pack()

MiniDump *mini_dump_new(gchar *filename,gchar *binary_directory);
gboolean mini_dump_open(MiniDump *self);
void mini_dump_close(MiniDump *self);
void mini_dump_free(MiniDump *self);
void mini_dump_print_stackwalk(MiniDump *self);
#endif
