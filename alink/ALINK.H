#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <string.h>
#include <limits.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>

#define TRUE (1 == 1)
#define FALSE (1 == 0)

#define SWITCHCHAR '-'
#ifdef _WIN32
#define PATH_CHAR '\\'
#define ALT_PATH_CHAR '/'
#else
#define PATH_CHAR '/'
#define ALT_PATH_CHAR '\\'
#endif
#define IS_PATH_CHAR(c) ((c) == PATH_CHAR || (c) == ALT_PATH_CHAR)
#define DEFAULT_EXTENSION ".obj"

#if defined(__GNUC__) || defined(__clang__)
#define ALINK_RETURNS_NONNULL __attribute__((returns_nonnull))
#else
#define ALINK_RETURNS_NONNULL
#endif

#define ERR_EXTRA_DATA 1
#define ERR_NO_HEADER 2
#define ERR_NO_RECDATA 3
#define ERR_NO_MEM 4
#define ERR_INV_DATA 5
#define ERR_INV_SEG 6
#define ERR_BAD_FIXUP 7
#define ERR_BAD_SEGDEF 8
#define ERR_ABS_SEG 9
#define ERR_DUP_PUBLIC 10
#define ERR_NO_MODEND 11
#define ERR_EXTRA_HEADER 12
#define ERR_UNKNOWN_RECTYPE 13
#define ERR_SEG_TOO_LARGE 14
#define ERR_MULTIPLE_STARTS 15
#define ERR_BAD_GRPDEF 16
#define ERR_OVERWRITE 17
#define ERR_INVALID_COMENT 18
#define ERR_ILLEGAL_IMPORTS 19

#define PREV_LE 1
#define PREV_LI 2
#define PREV_LI32 3

#define THEADR 0x80
#define LHEADR 0x82
#define COMENT 0x88
#define MODEND 0x8a
#define MODEND32 0x8b
#define EXTDEF 0x8c
#define TYPDEF 0x8e
#define PUBDEF 0x90
#define PUBDEF32 0x91
#define LINNUM 0x94
#define LINNUM32 0x95
#define LNAMES 0x96
#define SEGDEF 0x98
#define SEGDEF32 0x99
#define GRPDEF 0x9a
#define FIXUPP 0x9c
#define FIXUPP32 0x9d
#define LEDATA 0xa0
#define LEDATA32 0xa1
#define LIDATA 0xa2
#define LIDATA32 0xa3
#define COMDEF 0xb0
#define BAKPAT 0xb2
#define BAKPAT32 0xb3
#define LEXTDEF 0xb4
#define LEXTDEF32 0xb5
#define LPUBDEF 0xb6
#define LPUBDEF32 0xb7
#define LCOMDEF 0xb8
#define CEXTDEF 0xbc
#define COMDAT 0xc2
#define COMDAT32 0xc3
#define LINSYM 0xc4
#define LINSYM32 0xc5
#define ALIAS 0xc6
#define NBKPAT 0xc8
#define NBKPAT32 0xc9
#define LLNAMES 0xca
#define LIBHDR 0xf0
#define LIBEND 0xf1

#define COMENT_TRANSLATOR 0x00
#define COMENT_INTEL_COPYRIGHT 0x01
#define COMENT_LIB_SPEC 0x81
#define COMENT_MSDOS_VER 0x9c
#define COMENT_MEMMODEL 0x9d
#define COMENT_DOSSEG 0x9e
#define COMENT_DEFLIB 0x9f
#define COMENT_OMFEXT 0xa0
#define COMENT_NEWOMF 0xa1
#define COMENT_LINKPASS 0xa2
#define COMENT_LIBMOD 0xa3
#define COMENT_EXESTR 0xa4
#define COMENT_INCERR 0xa6
#define COMENT_NOPAD 0xa7
#define COMENT_WKEXT 0xa8
#define COMENT_LZEXT 0xa9
#define COMENT_PHARLAP 0xaa
#define COMENT_IBM386 0xb0
#define COMENT_RECORDER 0xb1
#define COMENT_COMMENT 0xda
#define COMENT_COMPILER 0xdb
#define COMENT_DATE 0xdc
#define COMENT_TIME 0xdd
#define COMENT_USER 0xdf
#define COMENT_DEPFILE 0xe9
#define COMENT_COMMANDLINE 0xff
#define COMENT_PUBTYPE 0xe1
#define COMENT_COMPARAM 0xea
#define COMENT_TYPDEF 0xe3
#define COMENT_STRUCTMEM 0xe2
#define COMENT_OPENSCOPE 0xe5
#define COMENT_LOCAL 0xe6
#define COMENT_ENDSCOPE 0xe7
#define COMENT_SOURCEFILE 0xe8

#define EXT_IMPDEF 0x01
#define EXT_EXPDEF 0x02

#define SEG_ALIGN 0x3e0
#define SEG_COMBINE 0x1c
#define SEG_BIG 0x02
#define SEG_USE32 0x01

#define SEG_ABS 0x00
#define SEG_BYTE 0x20
#define SEG_WORD 0x40
#define SEG_PARA 0x60
#define SEG_PAGE 0x80
#define SEG_DWORD 0xa0
#define SEG_MEMPAGE 0xc0
#define SEG_BADALIGN 0xe0
#define SEG_8BYTE 0x100
#define SEG_32BYTE 0x200
#define SEG_64BYTE 0x300

#define SEG_PRIVATE 0x00
#define SEG_PUBLIC 0x08
#define SEG_PUBLIC2 0x10
#define SEG_STACK 0x14
#define SEG_COMMON 0x18
#define SEG_PUBLIC3 0x1c

#define REL_SEGDISP 0
#define REL_EXTDISP 2
#define REL_GRPDISP 1
#define REL_EXPFRAME 3
#define REL_SEGONLY 4
#define REL_EXTONLY 6
#define REL_GRPONLY 5

#define REL_SEGFRAME 0
#define REL_GRPFRAME 1
#define REL_EXTFRAME 2
#define REL_LILEFRAME 4
#define REL_TARGETFRAME 5

#define FIX_SELFREL 0x10
#define FIX_MASK (0x0f + FIX_SELFREL)

#define FIX_THRED 0x08
#define THRED_MASK 0x07

#define FIX_LBYTE 0
#define FIX_OFS16 1
#define FIX_BASE 2
#define FIX_PTR1616 3
#define FIX_HBYTE 4
#define FIX_OFS16_2 5
#define FIX_OFS32 9
#define FIX_PTR1632 11
#define FIX_OFS32_2 13
/* RVA32 fixups are not supported by OMF, so has an out-of-range number */
#define FIX_RVA32 256

#define FIX_SELF_LBYTE (FIX_LBYTE + FIX_SELFREL)
#define FIX_SELF_OFS16 (FIX_OFS16 + FIX_SELFREL)
#define FIX_SELF_OFS16_2 (FIX_OFS16_2 + FIX_SELFREL)
#define FIX_SELF_OFS32 (FIX_OFS32 + FIX_SELFREL)
#define FIX_SELF_OFS32_2 (FIX_OFS32_2 + FIX_SELFREL)

#define LIBF_CASESENSITIVE 1

#define EXT_NOMATCH 0
#define EXT_MATCHEDPUBLIC 1
#define EXT_MATCHEDIMPORT 2

#define PE_SIGNATURE 0x00
#define PE_MACHINEID 0x04
#define PE_NUMOBJECTS 0x06
#define PE_DATESTAMP 0x08
#define PE_SYMBOLPTR 0x0c
#define PE_NUMSYMBOLS 0x10
#define PE_HDRSIZE 0x14
#define PE_FLAGS 0x16
#define PE_MAGIC 0x18
#define PE_LMAJOR 0x1a
#define PE_LMINOR 0x1b
#define PE_CODESIZE 0x1c
#define PE_INITDATASIZE 0x20
#define PE_UNINITDATASIZE 0x24
#define PE_ENTRYPOINT 0x28
#define PE_CODEBASE 0x2c
#define PE_DATABASE 0x30
#define PE_IMAGEBASE 0x34
#define PE_OBJECTALIGN 0x38
#define PE_FILEALIGN 0x3c
#define PE_OSMAJOR 0x40
#define PE_OSMINOR 0x42
#define PE_USERMAJOR 0x44
#define PE_USERMINOR 0x46
#define PE_SUBSYSMAJOR 0x48
#define PE_SUBSYSMINOR 0x4a
#define PE_IMAGESIZE 0x50
#define PE_HEADERSIZE 0x54
#define PE_CHECKSUM 0x58
#define PE_SUBSYSTEM 0x5c
#define PE_DLLFLAGS 0x5e
#define PE_STACKSIZE 0x60
#define PE_STACKCOMMSIZE 0x64
#define PE_HEAPSIZE 0x68
#define PE_HEAPCOMMSIZE 0x6c
#define PE_LOADERFLAGS 0x70
#define PE_NUMRVAS 0x74
#define PE_EXPORTRVA 0x78
#define PE_EXPORTSIZE 0x7c
#define PE_IMPORTRVA 0x80
#define PE_IMPORTSIZE 0x84
#define PE_RESOURCERVA 0x88
#define PE_RESOURCESIZE 0x8c
#define PE_EXCEPTIONRVA 0x90
#define PE_EXCEPTIONSIZE 0x94
#define PE_SECURITYRVA 0x98
#define PE_SECURITYSIZE 0x9c
#define PE_FIXUPRVA 0xa0
#define PE_FIXUPSIZE 0xa4
#define PE_DEBUGRVA 0xa8
#define PE_DEBUGSIZE 0xac
#define PE_DESCRVA 0xb0
#define PE_DESCSIZE 0xb4
#define PE_MSPECRVA 0xb8
#define PE_MSPECSIZE 0xbc
#define PE_TLSRVA 0xc0
#define PE_TLSSIZE 0xc4
#define PE_LOADCONFIGRVA 0xc8
#define PE_LOADCONFIGSIZE 0xcc
#define PE_BOUNDIMPRVA 0xd0
#define PE_BOUNDIMPSIZE 0xd4
#define PE_IATRVA 0xd8
#define PE_IATSIZE 0xdc

#define PE_OBJECT_NAME 0x00
#define PE_OBJECT_VIRTSIZE 0x08
#define PE_OBJECT_VIRTADDR 0x0c
#define PE_OBJECT_RAWSIZE 0x10
#define PE_OBJECT_RAWPTR 0x14
#define PE_OBJECT_RELPTR 0x18
#define PE_OBJECT_LINEPTR 0x1c
#define PE_OBJECT_NUMREL 0x20
#define PE_OBJECT_NUMLINE 0x22
#define PE_OBJECT_FLAGS 0x24

#define PE_BASE_HEADER_SIZE 0x18
#define PE_OPTIONAL_HEADER_SIZE 0xe0
#define PE_OBJECTENTRY_SIZE 0x28
#define PE_HEADBUF_SIZE (PE_BASE_HEADER_SIZE + PE_OPTIONAL_HEADER_SIZE)
#define PE_IMPORTDIRENTRY_SIZE 0x14
#define PE_NUM_VAS 0x10
#define PE_EXPORTHEADER_SIZE 0x28
#define PE_RESENTRY_SIZE 0x08
#define PE_RESDIR_SIZE 0x10
#define PE_RESDATAENTRY_SIZE 0x10
#define PE_SYMBOL_SIZE 0x12
#define PE_RELOC_SIZE 0x0a

#define PE_ORDINAL_FLAG 0x80000000
#define PE_INTEL386 0x014c
#define PE_MAGICNUM 0x010b
#define PE_FILE_EXECUTABLE 0x0002
#define PE_FILE_32BIT 0x0100
#define PE_FILE_LIBRARY 0x2000

#define PE_REL_LOW16 0x2000
#define PE_REL_OFS32 0x3000

#define PE_SUBSYS_NATIVE 1
#define PE_SUBSYS_WINDOWS 2
#define PE_SUBSYS_CONSOLE 3
#define PE_SUBSYS_POSIX 7

#define WINF_UNDEFINED 0x00000000
#define WINF_CODE 0x00000020
#define WINF_INITDATA 0x00000040
#define WINF_UNINITDATA 0x00000080
#define WINF_DISCARDABLE 0x02000000
#define WINF_NOPAGE 0x08000000
#define WINF_SHARED 0x10000000
#define WINF_EXECUTE 0x20000000
#define WINF_READABLE 0x40000000
#define WINF_WRITEABLE 0x80000000
#define WINF_ALIGN_NOPAD 0x00000008
#define WINF_ALIGN_BYTE 0x00100000
#define WINF_ALIGN_WORD 0x00200000
#define WINF_ALIGN_DWORD 0x00300000
#define WINF_ALIGN_8 0x00400000
#define WINF_ALIGN_PARA 0x00500000
#define WINF_ALIGN_32 0x00600000
#define WINF_ALIGN_64 0x00700000
#define WINF_ALIGN (WINF_ALIGN_64)
#define WINF_COMMENT 0x00000200
#define WINF_REMOVE 0x00000800
#define WINF_COMDAT 0x00001000
#define WINF_NEG_FLAGS (WINF_DISCARDABLE | WINF_NOPAGE)
#define WINF_IMAGE_FLAGS 0xfa0008e0

#define COMDAT_CONTINUE 0x01
#define COMDAT_ITERATED 0x02
#define COMDAT_LOCAL 0x04

#define COMDAT_ALLOC_MASK 0x0f
#define COMDAT_EXPLICIT 0x00
#define COMDAT_FAR_CODE 0x01
#define COMDAT_FAR_DATA 0x02
#define COMDAT_CODE32 0x03
#define COMDAT_DATA32 0x04

#define COMDAT_MATCH_MASK 0xf0
#define COMDAT_MATCH_NONE 0x00
#define COMDAT_MATCH_ANY 0x10
#define COMDAT_MATCH_SAME 0x20
#define COMDAT_MATCH_EXACT 0x30

#define COMDAT_ALIGN_SEG 0x00
#define COMDAT_ALIGN_BYTE 0x01
#define COMDAT_ALIGN_WORD 0x02
#define COMDAT_ALIGN_PARA 0x03
#define COMDAT_ALIGN_4K 0x04
#define COMDAT_ALIGN_DWORD 0x05

#define COFF_SYM_EXTERNAL 2
#define COFF_SYM_STATIC 3
#define COFF_SYM_LABEL 6
#define COFF_SYM_FUNCTION 101
#define COFF_SYM_FILE 103
#define COFF_SYM_SECTION 104

#define COFF_FIX_DIR32 6
#define COFF_FIX_RVA32 7
#define COFF_FIX_REL32 0x14

#define OUTPUT_COM 1
#define OUTPUT_EXE 2
#define OUTPUT_PE 3

#define WIN32_DEFAULT_BASE 0x00400000
#define WIN32_DEFAULT_FILEALIGN 0x00000200
#define WIN32_DEFAULT_OBJECTALIGN 0x00001000
#define WIN32_DEFAULT_STACKSIZE 0x00100000
#define WIN32_DEFAULT_STACKCOMMITSIZE 0x00001000
#define WIN32_DEFAULT_HEAPSIZE 0x00100000
#define WIN32_DEFAULT_HEAPCOMMITSIZE 0x00001000
#define WIN32_DEFAULT_SUBSYS PE_SUBSYS_WINDOWS
#define WIN32_DEFAULT_SUBSYSMAJOR 4
#define WIN32_DEFAULT_SUBSYSMINOR 0
#define WIN32_DEFAULT_OSMAJOR 1
#define WIN32_DEFAULT_OSMINOR 0

#define EXP_ORD 0x80

typedef char *PCHAR, **PPCHAR;
typedef unsigned char *PUCHAR;
typedef unsigned int UINT;

typedef struct __sortentry
{
    char *id;
    void **object;
    UINT count;
} SORTENTRY, *PSORTENTRY;

typedef struct __seg
{
    long nameindex;
    long classindex;
    long overlayindex;
    long orderindex;
    UINT length;
    UINT virtualSize;
    UINT absframe;
    UINT absofs;
    UINT base;
    UINT winFlags;
    unsigned short attr;
    PUCHAR data;
    PUCHAR datmask;
} SEG, *PSEG, **PPSEG;

typedef struct __datablock
{
    long count;
    long blocks;
    long dataofs;
    void *data;
} DATABLOCK, *PDATABLOCK, **PPDATABLOCK;

typedef struct __pubdef
{
    long segnum;
    long grpnum;
    long typenum;
    UINT ofs;
    UINT modnum;
    PCHAR aliasName;
} PUBLIC, *PPUBLIC, **PPPUBLIC;

typedef struct __extdef
{
    PCHAR name;
    long typenum;
    PPUBLIC pubdef;
    long impnum;
    long flags;
    UINT modnum;
} EXTREC, *PEXTREC, **PPEXTREC;

typedef struct __imprec
{
    PCHAR int_name;
    PCHAR mod_name;
    PCHAR imp_name;
    unsigned short ordinal;
    char flags;
    long segnum;
    UINT ofs;
} IMPREC, *PIMPREC, **PPIMPREC;

typedef struct __exprec
{
    PCHAR int_name;
    PCHAR exp_name;
    UINT ordinal;
    char flags;
    PPUBLIC pubdef;
    UINT modnum;
} EXPREC, *PEXPREC, **PPEXPREC;

typedef struct __comdef
{
    PCHAR name;
    UINT length;
    int isFar;
    UINT modnum;
} COMREC, *PCOMREC, **PPCOMREC;

typedef struct __reloc
{
    UINT ofs;
    long segnum;
    unsigned char ftype, ttype;
    unsigned short rtype;
    long target;
    UINT disp;
    long frame;
    UINT outputPos;
} RELOC, *PRELOC, **PPRELOC;

typedef struct __grp
{
    long nameindex;
    long numsegs;
    long segindex[256];
    long segnum;
} GRP, *PGRP, **PPGRP;

typedef struct __libfile
{
    PCHAR filename;
    unsigned short blocksize;
    unsigned short numdicpages;
    UINT dicstart;
    char flags;
    char libtype;
    int modsloaded;
    UINT *modlist;
    PUCHAR longnames;
    PSORTENTRY symbols;
    UINT numsyms;
} LIBFILE, *PLIBFILE, **PPLIBFILE;

typedef struct __libentry
{
    UINT libfile;
    UINT modpage;
} LIBENTRY, *PLIBENTRY, **PPLIBENTRY;

typedef struct __resource
{
    PUCHAR typename;
    PUCHAR name;
    PUCHAR data;
    UINT length;
    unsigned short typeid;
    unsigned short id;
    unsigned short languageid;
} RESOURCE, *PRESOURCE;

typedef struct __coffsym
{
    PUCHAR name;
    UINT value;
    short section;
    unsigned short type;
    unsigned char class;
    long extnum;
    UINT numAuxRecs;
    PUCHAR auxRecs;
    int isComDat;
} COFFSYM, *PCOFFSYM;

typedef struct __comdatrec
{
    UINT segnum;
    UINT combineType;
    UINT linkwith;
    UINT modnum;
    UINT flags;
    PPUBLIC pubdef;
} COMDATREC, *PCOMDAT;

int sortCompare(const void *x1, const void *x2);
void processArgs(int argc, char *argv[]);
void combine_groups(long i, long j);
void combine_common(long i, long j);
void combine_segments(long i, long j);
void combineBlocks();
void redirect_segment(long dest, long src);
void OutputWin32file(PCHAR outname);
void OutputEXEfile(PCHAR outname);
void OutputCOMfile(PCHAR outname);
void GetFixupTarget(PRELOC r, long *tseg, UINT *tofs, int isFlat);
void loadlibmod(UINT libnum, UINT modpage);
void loadlib(FILE *libfile, PCHAR libname);
void loadCoffLib(FILE *libfile, PCHAR libname);
void loadcofflibmod(PLIBFILE p, FILE *libfile);
long loadmod(FILE *objfile);
void loadres(FILE *resfile);
void loadcoff(FILE *objfile);
void loadCoffImport(FILE *objfile);
void LoadFIXUP(PRELOC r, PUCHAR buf, long *p);
void RelocLIDATA(PDATABLOCK p, long *ofs, PRELOC r);
void EmitLiData(PDATABLOCK p, long segnum, long *ofs);
PDATABLOCK BuildLiData(long *bufofs);
void DestroyLIDATA(PDATABLOCK p);
void ReportError(long errnum);
long GetIndex(PUCHAR buf, long *index);
void ClearNbit(PUCHAR mask, long i);
void SetNbit(PUCHAR mask, long i);
char GetNbit(PUCHAR mask, long i);
int wstricmp(const char *s1, const char *s2);
int wstrlen(const char *s);
unsigned short wtoupper(unsigned short a);
int getBitCount(UINT a);
void *checkMalloc(size_t x) ALINK_RETURNS_NONNULL;
void *checkRealloc(void *p, size_t x) ALINK_RETURNS_NONNULL;
char *checkStrdup(const char *s) ALINK_RETURNS_NONNULL;
int stricmp(const char *s1, const char *s2);
char *strupr(char *s);
char *_strdup(const char *s);
PSORTENTRY binarySearch(PSORTENTRY list, UINT count, char *key);
void sortedInsert(PSORTENTRY *plist, UINT *pcount, char *key, void *object);
#define strdup _strdup

extern char case_sensitive;
extern char padsegments;
extern char mapfile;
extern PCHAR mapname;
extern unsigned short maxalloc;
extern int output_type;
extern PCHAR outname;

extern FILE *afile;
extern UINT filepos;
extern long reclength;
extern unsigned char rectype;
extern char li_le;
extern UINT prevofs;
extern long prevseg;
extern long gotstart;
extern RELOC startaddr;
extern UINT imageBase;
extern UINT fileAlign;
extern UINT objectAlign;
extern UINT stackSize;
extern UINT stackCommitSize;
extern UINT heapSize;
extern UINT heapCommitSize;
extern unsigned char osMajor, osMinor;
extern unsigned char subsysMajor, subsysMinor;
extern unsigned int subSystem;

extern long errcount;

extern unsigned char buf[65536];
extern PDATABLOCK lidata;

extern PPCHAR namelist;
extern PPSEG seglist;
extern PPSEG outlist;
extern PPGRP grplist;
extern PSORTENTRY publics;
extern PEXTREC externs;
extern PPCOMREC comdefs;
extern PPRELOC relocs;
extern PIMPREC impdefs;
extern PEXPREC expdefs;
extern PLIBFILE libfiles;
extern PRESOURCE resource;
extern PPCHAR modname;
extern PPCHAR filename;
extern PSORTENTRY comdats;
extern UINT comdatcount;
extern UINT namecount, namemin, pubcount, pubmin, segcount, segmin, outcount, grpcount, grpmin,
    extcount, extmin, comcount, commin, fixcount, fixmin, impcount, impmin, impsreq, expcount,
    expmin, nummods, filecount, libcount, rescount;

extern int buildDll;
extern PUCHAR stubName;
