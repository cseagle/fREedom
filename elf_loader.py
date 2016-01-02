#!/usr/bin/env python

'''
Crude ELF loader, conforming to the Loader interface, for a stand-alone binnavi compatible disassembler
'''

__author__ = "Chris Eagle"
__copyright__ = "Copyright 2015, Chris Eagle"
__credits__ = ["Chris Eagle"]
__license__ = "GPL"
__version__ = "2.0"
__maintainer__ = "Chris Eagle"
__email__ = "cseagle@gmail.com"
__status__ = "Use at your own risk"

import sys
import struct
import hashlib
import binascii
import capstone
from loader import *

XR_FLOW = 1
XR_CALL = 2
XR_JUMP = 3
XR_JCC  = 4

EI_CLASS    = 4        # File class byte index
ELFCLASSNONE = 0    # Invalid class
ELFCLASS32  = 1     # 32-bit objects
ELFCLASS64  = 2     # 64-bit objects
ELFCLASSNUM = 3

EI_DATA     = 5     # Data encoding byte index
ELFDATANONE = 0     # Invalid data encoding
ELFDATA2LSB = 1     # 2's complement, little endian
ELFDATA2MSB = 2     # 2's complement, big endian
ELFDATANUM  = 3

EI_VERSION  = 6     # File version byte index
      # Value must be EV_CURRENT

EI_OSABI = 7     # OS ABI identification
ELFOSABI_NONE    = 0  # UNIX System V ABI
ELFOSABI_SYSV    = 0  # Alias.
ELFOSABI_HPUX    = 1  # HP-UX
ELFOSABI_NETBSD  = 2  # NetBSD.
ELFOSABI_GNU     = 3  # Object uses GNU ELF extensions.
ELFOSABI_LINUX   = ELFOSABI_GNU # Compatibility alias.
ELFOSABI_SOLARIS = 6  # Sun Solaris.
ELFOSABI_AIX     = 7  # IBM AIX.
ELFOSABI_IRIX    = 8  # SGI Irix.
ELFOSABI_FREEBSD = 9  # FreeBSD.
ELFOSABI_TRU64   = 10 # Compaq TRU64 UNIX.
ELFOSABI_MODESTO = 11 # Novell Modesto.
ELFOSABI_OPENBSD = 12 # OpenBSD.
ELFOSABI_ARM_AEABI = 64 # ARM EABI
ELFOSABI_ARM     = 97 # ARM
ELFOSABI_STANDALONE = 255   # Standalone (embedded) application

EI_ABIVERSION = 8     # ABI version

EI_PAD    = 9     # Byte index of padding bytes

# Legal values for e_type (object file type).

ET_NONE   = 0     # No file type
ET_REL    = 1     # Relocatable file
ET_EXEC   = 2     # Executable file
ET_DYN    = 3     # Shared object file
ET_CORE   = 4     # Core file
ET_NUM    = 5     # Number of defined types
ET_LOOS   = 0xfe00      # OS-specific range start
ET_HIOS   = 0xfeff      # OS-specific range end
ET_LOPROC = 0xff00      # Processor-specific range start
ET_HIPROC = 0xffff      # Processor-specific range end


EM_NONE    =  0    # No machine
EM_SPARC   =  2    # SUN SPARC
EM_386     =  3    # Intel 80386
EM_68K     =  4    # Motorola m68k family
EM_MIPS    =  8    # MIPS R3000 big-endian
EM_MIPS_RS3_LE = 10 # MIPS R3000 little-endian

EM_PPC     =  20    # PowerPC
EM_PPC64   =  21    # PowerPC 64-bit

EM_ARM     =  40    # ARM
EM_SPARCV9 =  43    # SPARC v9 64-bit

EM_X86_64  =  62    # AMD x86-64 architecture

EM_AARCH64 =  183   # ARM AARCH64

# Legal values for p_type (segment type).

PT_NULL     = 0     # Program header table entry unused
PT_LOAD     = 1     # Loadable program segment
PT_DYNAMIC  = 2     # Dynamic linking information
PT_INTERP   = 3     # Program interpreter
PT_NOTE     = 4     # Auxiliary information
PT_SHLIB    = 5     # Reserved
PT_PHDR     = 6     # Entry for header table itself
PT_TLS      = 7     # Thread-local storage segment
PT_NUM      = 8     # Number of defined types
PT_LOOS     = 0x60000000  # Start of OS-specific
PT_GNU_EH_FRAME   = 0x6474e550  # GCC .eh_frame_hdr segment
PT_GNU_STACK   = 0x6474e551  # Indicates stack executability
PT_GNU_RELRO   = 0x6474e552  # Read-only after relocation
PT_LOSUNW   = 0x6ffffffa
PT_SUNWBSS  = 0x6ffffffa  # Sun Specific segment
PT_SUNWSTACK = 0x6ffffffb  # Stack segment
PT_HISUNW   = 0x6fffffff
PT_HIOS     = 0x6fffffff  # End of OS-specific
PT_LOPROC   = 0x70000000  # Start of processor-specific
PT_HIPROC   = 0x7fffffff  # End of processor-specific

# Legal values for e_version (version).

EV_NONE     = 0     # Invalid ELF version
EV_CURRENT  = 1     # Current version
EV_NUM      = 2

# Legal values for p_flags (segment flags).

PF_X        = (1 << 0) # Segment is executable
PF_W        = (1 << 1) # Segment is writable
PF_R        = (1 << 2) # Segment is readable
PF_MASKOS   = 0x0ff00000  # OS-specific
PF_MASKPROC = 0xf0000000  # Processor-specific

# Legal values for sh_type (section type).

SHT_NULL  = 0     # Section header table entry unused
SHT_PROGBITS   = 1      # Program data
SHT_SYMTAB  = 2      # Symbol table
SHT_STRTAB  = 3      # String table
SHT_RELA = 4      # Relocation entries with addends
SHT_HASH = 5      # Symbol hash table
SHT_DYNAMIC = 6      # Dynamic linking information
SHT_NOTE = 7      # Notes
SHT_NOBITS  = 8      # Program space with no data (bss)
SHT_REL     = 9      # Relocation entries, no addends
SHT_SHLIB   = 10     # Reserved
SHT_DYNSYM  = 11     # Dynamic linker symbol table
SHT_INIT_ARRAY = 14     # Array of constructors
SHT_FINI_ARRAY = 15     # Array of destructors
SHT_PREINIT_ARRAY = 16    # Array of pre-constructors
SHT_GROUP   = 17     # Section group
SHT_SYMTAB_SHNDX = 18    # Extended section indeces
SHT_NUM     = 19     # Number of defined types.
SHT_LOOS = 0x60000000   # Start OS-specific.
SHT_GNU_ATTRIBUTES = 0x6ffffff5 # Object attributes.
SHT_GNU_HASH   = 0x6ffffff6   # GNU-style hash table.
SHT_GNU_LIBLIST   = 0x6ffffff7   # Prelink library list
SHT_CHECKSUM   = 0x6ffffff8   # Checksum for DSO content.
SHT_LOSUNW   = 0x6ffffffa   # Sun-specific low bound.
SHT_SUNW_move   = 0x6ffffffa
SHT_SUNW_COMDAT  = 0x6ffffffb
SHT_SUNW_syminfo = 0x6ffffffc
SHT_GNU_verdef  = 0x6ffffffd   # Version definition section.
SHT_GNU_verneed   = 0x6ffffffe   # Version needs section.
SHT_GNU_versym  = 0x6fffffff   # Version symbol table.
SHT_HISUNW   = 0x6fffffff   # Sun-specific high bound.
SHT_HIOS  = 0x6fffffff   # End OS-specific type
SHT_LOPROC  = 0x70000000   # Start of processor-specific
SHT_HIPROC  = 0x7fffffff   # End of processor-specific
SHT_LOUSER  = 0x80000000   # Start of application-specific
SHT_HIUSER  = 0x8fffffff   # End of application-specific

# Legal values for sh_flags (section flags).

SHF_WRITE        = (1 << 0)  # Writable
SHF_ALLOC        = (1 << 1)  # Occupies memory during execution
SHF_EXECINSTR    = (1 << 2)  # Executable
SHF_MERGE        = (1 << 4)  # Might be merged
SHF_STRINGS      = (1 << 5)  # Contains nul-terminated strings
SHF_INFO_LINK    = (1 << 6)  # `sh_info' contains SHT index
SHF_LINK_ORDER   = (1 << 7)  # Preserve order after combining
SHF_OS_NONCONFORMING = (1 << 8) # Non-standard OS specific handling required
SHF_GROUP       = (1 << 9)  # Section is member of a group.
SHF_TLS         = (1 << 10) # Section hold thread-local data.
SHF_MASKOS      = 0x0ff00000   # OS-specific.
SHF_MASKPROC    = 0xf0000000   # Processor-specific
SHF_ORDERED     = (1 << 30) # Special ordering requirement (Solaris).
SHF_EXCLUDE     = (1 << 31) # Section is excluded unless referenced or allocated (Solaris).

# Legal values for ST_TYPE subfield of st_info (symbol type).

STT_NOTYPE   = 0     # Symbol type is unspecified
STT_OBJECT   = 1     # Symbol is a data object
STT_FUNC     = 2     # Symbol is a code object
STT_SECTION  = 3     # Symbol associated with a section
STT_FILE     = 4     # Symbol's name is file name
STT_COMMON   = 5     # Symbol is a common data object
STT_TLS      = 6     # Symbol is thread-local data object
STT_NUM      = 7     # Number of defined types.
STT_LOOS     = 10    # Start of OS-specific
STT_GNU_IFUNC = 10    # Symbol is indirect code object
STT_HIOS     = 12    # End of OS-specific
STT_LOPROC   = 13    # Start of processor-specific
STT_HIPROC   = 15    # End of processor-specific

# Legal values for d_tag (dynamic entry type).

DT_NULL      = 0     # Marks end of dynamic section
DT_NEEDED    = 1     # Name of needed library
DT_PLTRELSZ  = 2     # Size in bytes of PLT relocs
DT_PLTGOT    = 3     # Processor defined value
DT_HASH      = 4     # Address of symbol hash table
DT_STRTAB    = 5     # Address of string table
DT_SYMTAB    = 6     # Address of symbol table
DT_RELA      = 7     # Address of Rela relocs
DT_RELASZ    = 8     # Total size of Rela relocs
DT_RELAENT   = 9     # Size of one Rela reloc
DT_STRSZ     = 10    # Size of string table
DT_SYMENT    = 11    # Size of one symbol table entry
DT_INIT      = 12    # Address of init function
DT_FINI      = 13    # Address of termination function
DT_SONAME    = 14    # Name of shared object
DT_RPATH     = 15    # Library search path (deprecated)
DT_SYMBOLIC  = 16    # Start symbol search here
DT_REL       = 17    # Address of Rel relocs
DT_RELSZ     = 18    # Total size of Rel relocs
DT_RELENT    = 19    # Size of one Rel reloc
DT_PLTREL    = 20    # Type of reloc in PLT
DT_DEBUG     = 21    # For debugging; unspecified
DT_TEXTREL   = 22    # Reloc might modify .text
DT_JMPREL    = 23    # Address of PLT relocs
DT_BIND_NOW  = 24    # Process relocations of object
DT_INIT_ARRAY = 25    # Array with addresses of init fct
DT_FINI_ARRAY = 26    # Array with addresses of fini fct
DT_INIT_ARRAYSZ   = 27    # Size in bytes of DT_INIT_ARRAY
DT_FINI_ARRAYSZ   = 28    # Size in bytes of DT_FINI_ARRAY
DT_RUNPATH   = 29    # Library search path
DT_FLAGS     = 30    # Flags for the object being loaded
DT_ENCODING  = 32    # Start of encoded range
DT_PREINIT_ARRAY = 32      # Array with addresses of preinit fct
DT_PREINIT_ARRAYSZ = 33    # size in bytes of DT_PREINIT_ARRAY
DT_NUM       = 34    # Number used
DT_LOOS      = 0x6000000d  # Start of OS-specific
DT_HIOS      = 0x6ffff000  # End of OS-specific
DT_LOPROC    = 0x70000000  # Start of processor-specific
DT_HIPROC    = 0x7fffffff  # End of processor-specific
#DT_PROCNUM  = DT_MIPS_NUM # Most used by any processor

# DT_* entries which fall between DT_VALRNGHI & DT_VALRNGLO use the
#   Dyn.d_un.d_val field of the Elf*_Dyn structure.  This follows Sun's
#   approach.
DT_VALRNGLO  = 0x6ffffd00
DT_GNU_PRELINKED  = 0x6ffffdf5 # Prelinking timestamp
DT_GNU_CONFLICTSZ = 0x6ffffdf6   # Size of conflict section
DT_GNU_LIBLISTSZ  = 0x6ffffdf7 # Size of library list
DT_CHECKSUM  = 0x6ffffdf8
DT_PLTPADSZ  = 0x6ffffdf9
DT_MOVEENT   = 0x6ffffdfa
DT_MOVESZ    = 0x6ffffdfb
DT_FEATURE_1 = 0x6ffffdfc  # Feature selection (DTF_*).
DT_POSFLAG_1 = 0x6ffffdfd  # Flags for DT_* entries, effecting the following DT_* entry.
DT_SYMINSZ   = 0x6ffffdfe  # Size of syminfo table (in bytes)
DT_SYMINENT  = 0x6ffffdff  # Entry size of syminfo
DT_VALRNGHI  = 0x6ffffdff
#DT_VALTAGIDX(tag)  (DT_VALRNGHI - (tag))   # Reverse order!
DT_VALNUM    = 12

# DT_* entries which fall between DT_ADDRRNGHI & DT_ADDRRNGLO use the
#   Dyn.d_un.d_ptr field of the Elf*_Dyn structure.

#   If any adjustment is made to the ELF object after it has been
#   built these entries will need to be adjusted.
DT_ADDRRNGLO = 0x6ffffe00
DT_GNU_HASH  = 0x6ffffef5  # GNU-style hash table.
DT_TLSDESC_PLT  = 0x6ffffef6
DT_TLSDESC_GOT  = 0x6ffffef7
DT_GNU_CONFLICT = 0x6ffffef8  # Start of conflict section
DT_GNU_LIBLIST  = 0x6ffffef9  # Library list
DT_CONFIG    = 0x6ffffefa  # Configuration information.
DT_DEPAUDIT  = 0x6ffffefb  # Dependency auditing.
DT_AUDIT     = 0x6ffffefc  # Object auditing.
DT_PLTPAD    = 0x6ffffefd  # PLT padding.
DT_MOVETAB   = 0x6ffffefe  # Move table.
DT_SYMINFO   = 0x6ffffeff  # Syminfo table.
DT_ADDRRNGHI = 0x6ffffeff
#DT_ADDRTAGIDX(tag) (DT_ADDRRNGHI - (tag))  # Reverse order!
DT_ADDRNUM   = 11

# The versioning entry types.  The next are defined as part of the GNU extension.
DT_VERSYM    = 0x6ffffff0

DT_RELACOUNT = 0x6ffffff9
DT_RELCOUNT  = 0x6ffffffa

# These were chosen by Sun.
DT_FLAGS_1   = 0x6ffffffb  # State flags, see DF_1_* below.
DT_VERDEF    = 0x6ffffffc  # Address of version definition table
DT_VERDEFNUM = 0x6ffffffd  # Number of version definitions
DT_VERNEED   = 0x6ffffffe  # Address of table with needed versions
DT_VERNEEDNUM  = 0x6fffffff  # Number of needed versions
#DT_VERSIONTAGIDX(tag) (DT_VERNEEDNUM - (tag)) # Reverse order!
DT_VERSIONTAGNUM = 16

# Sun added these machine-independent extensions in the "processor-specific" range.  Be compatible.
DT_AUXILIARY    = 0x7ffffffd      # Shared object to load before self
DT_FILTER       = 0x7fffffff      # Shared object to get values from
#DT_EXTRATAGIDX(tag)   ((Elf32_Word)-((Elf32_Sword) (tag) <<1>>1)-1)
DT_EXTRANUM     = 3

class InvalidHeader(Exception):
   def __init__(self, msg):
      Exception.__init__(self, msg)

class ElfSectionHeader(object):
   # do our best to handle both Elf32_Shdr and Elf64_Shdr
   def __init__(self, elf, offset):
      try:
         self.raw = elf.raw[offset:offset+elf.e_shentsize]
         if elf.sizeof_ptr == 8:
            fields = struct.unpack(elf.endian + "IIQQQQIIQQ", self.raw)
         else:
            fields = struct.unpack(elf.endian + "IIIIIIIIII", self.raw)
         self.sh_name = fields[0]
         self.sh_type = fields[1]
         self.sh_flags = fields[2]
         self.sh_addr = fields[3]
         self.sh_offset = fields[4]
         self.sh_size = fields[5]
         self.sh_link = fields[6]
         self.sh_info = fields[7]
         self.sh_addralign = fields[8]
         self.sh_entsize = fields[9]

         self.perms = PROT_READ

         if self.sh_type == SHT_NOBITS:
            size = 0
         else:
            size = self.sh_size

         if self.sh_flags & SHF_WRITE:
            self.perms |= PROT_WRITE
         if self.sh_flags & SHF_EXECINSTR:
            self.perms |= PROT_EXEC
            
         self.content = elf.raw

      except:
         raise InvalidHeader("Invalid section header")

   def __del__(self):
      del self.raw

   def get_string(self, offset):
      #if this isn't a STRTAB section we should probably throw an exception
      res = ''
      while offset < self.sh_size:
         ch = self.content[self.sh_offset + offset]
         if ch == '\x00':
            break
         res += ch
         offset += 1
      return res

class ElfProgramHeader(object):
   # do our best to handle both Elf32_Phdr and Elf64_Phdr
   def __init__(self, elf, offset):
      try:
         self.raw = elf.raw[offset:offset+elf.e_phentsize]
         i = elf.sizeof_ptr >> 2
         if elf.sizeof_ptr == 8:
            fields = struct.unpack(elf.endian + "IIQQQQQQ", self.raw)
            self.p_flags = fields[1]
         else:
            fields = struct.unpack(elf.endian + "IIIIIIII", self.raw)
            self.p_flags = fields[6]

         self.p_type = fields[0]
         self.p_offset = fields[i]
         self.p_vaddr = fields[i + 1]
         self.p_paddr = fields[i + 2]
         self.p_filesz = fields[i + 3]
         self.p_memsz = fields[i + 4]
         self.p_align = fields[7]

         self.perms = 0
         if self.p_flags & PF_R:
            self.perms |= PROT_READ
         if self.p_flags & PF_W:
            self.perms |= PROT_WRITE
         if self.p_flags & PF_X:
            self.perms |= PROT_EXEC

         if self.p_type == PT_DYNAMIC:
            self.dyns = {}
            dyn_size = 2 * elf.sizeof_ptr
            num_dyns = self.p_filesz // dyn_size
            for i in range(num_dyns):
               d_tag = elf.get_pointer(self.p_vaddr + i * dyn_size)
               d_un = elf.get_pointer(self.p_vaddr + i * dyn_size + elf.sizeof_ptr)
               if d_tag == DT_NEEDED:
                  if d_tag not in self.dyns:
                     self.dyns[d_tag] = []
                  self.dyns[d_tag].append(d_un)
               elif d_tag == DT_NULL:
                  break
               elif d_tag == DT_STRTAB:
                  if elf.symbol_strtab is not None:
                     #print "Existing strtab: 0x%x" % elf.symbol_strtab
                     #print "DT_STRTAB: 0x%x" % d_un
                     pass
                  elf.symbol_strtab = d_un
               else:
                  if d_tag in self.dyns:
                     print "Unexpected duplicate of d_tag %d" % d_tag
                  self.dyns[d_tag] = d_un
      except:
         raise InvalidHeader("Invalid program header")

   def __del__(self):
      del self.raw

class ElfSymbol(object):

   def __init__(self, name, value, size, info, other, shndx):
      self.name = name
      self.value = value
      self.size = size
      self.info = info
      self.other = other
      self.shndx = shndx
      self.bind = (info >> 4) & 0xf
      self.type = info & 0xf

   def __del__(self):
      del self.name

class ElfBase(Loader):

   def __init__(self, elf_file):
      Loader.__init__(self, elf_file)

      self.pe_offset = 0
      self.shdrs = []
      self.phdrs = []
      self.symbols = []

      #need algorithm to propogate this attribute to callers when possible
      self.non_returning_funcs.append("abort")
      self.non_returning_funcs.append("err")
      self.non_returning_funcs.append("errx")
      self.non_returning_funcs.append("exit")
      self.non_returning_funcs.append("_exit")
      self.non_returning_funcs.append("__assert_fail")
      self.non_returning_funcs.append("pthread_exit")
      self.non_returning_funcs.append("verr")
      self.non_returning_funcs.append("verrx")

   def __del__(self):
      del self.shdrs[:]
      del self.shdrs
      del self.phdrs[:]
      del self.phdrs
      del self.symbols[:]
      del self.symbols
      Loader.__del__(self)

   # Perform common PE validation tasks
   def is_valid(self):
      if self.raw[0:4] != '\x7fELF':
         return False

      if ord(self.raw[EI_VERSION]) != EV_CURRENT:
         return False

      if ord(self.raw[EI_CLASS]) != ELFCLASS32 and ord(self.raw[EI_CLASS]) != ELFCLASS64:
         return False

      if ord(self.raw[EI_DATA]) != ELFDATA2MSB and ord(self.raw[EI_DATA]) != ELFDATA2LSB:
         return False

      if ord(self.raw[EI_DATA]) == ELFDATA2MSB:
         self.set_endianness(BIG_ENDIAN)

      self.e_type = self.get_word(16)

      if self.e_type < ET_REL or self.e_type > ET_CORE:
         return False

      self.e_machine = self.get_word(18)

      if self.e_machine == EM_386:
         self.arch = capstone.CS_ARCH_X86
         self.mode = capstone.CS_MODE_32
         self.arch_name = 'x86-32'
      elif self.e_machine == EM_X86_64:
         self.arch = capstone.CS_ARCH_X86
         self.mode = capstone.CS_MODE_64
         self.arch_name = 'x86-64'
      elif self.e_machine == EM_ARM:
         self.arch = capstone.CS_ARCH_ARM
         self.mode = capstone.CS_MODE_ARM
         self.arch_name = 'ARM'
      elif self.e_machine == EM_AARCH64:
         self.arch = capstone.CS_ARCH_ARM64
         self.mode = capstone.CS_MODE_ARM
         self.arch_name = 'AARCH64'
      elif self.e_machine == EM_PPC:
         self.arch = capstone.CS_ARCH_PPC
         self.mode = capstone.CS_MODE_32
         self.arch_name = 'PPC'
      elif self.e_machine == EM_PPC64:
         self.arch = capstone.CS_ARCH_PPC
         self.mode = capstone.CS_MODE_64
         self.arch_name = 'PPC-64'
      elif self.e_machine == EM_SPARC:
         self.arch = capstone.CS_ARCH_SPARC
         self.mode = capstone.CS_MODE_32
         self.arch_name = 'SPARC'
      elif self.e_machine == EM_MIPS:
         self.arch = capstone.CS_ARCH_MIPS
         if self.sizeof_ptr == 4:
            self.mode = capstone.CS_MODE_MIPS32
            self.arch_name = 'MIPS32'
         elif self.sizeof_ptr == 8:
            self.mode = capstone.CS_MODE_MIPS64
            self.arch_name = 'MIPS64'
      else:
         # anything else, we don't recognize
         # could move this check into the caller
         # to allow it to determine whether it has an appropriate
         # disassembler
         return False

      if self.endian == BIG_ENDIAN:
         self.mode |= capstone.CS_MODE_BIG_ENDIAN

      self.e_version = self.get_dword(20)
      self.e_entry = self.get_pointer(24)
      self.e_phoff = self.get_pointer(24 + self.sizeof_ptr)
      self.e_shoff = self.get_pointer(24 + self.sizeof_ptr * 2)
      self.e_flags = self.get_dword(24 + self.sizeof_ptr * 3)
      fields_offset = 28 + self.sizeof_ptr * 3
      fields = []
      for i in range(6):
         # could do all this with struct.unpack, would need to ensure
         # we honor endian-ness in the format string that is used
         fields.append(self.get_word(fields_offset + i * 2))
      self.e_ehsize = fields[0]
      self.e_phentsize = fields[1]
      self.e_phnum = fields[2]
      self.e_shentsize = fields[3]
      self.e_shnum = fields[4]
      self.e_shstrndx = fields[5]

      self.symbol_strtab = None

      # some sanity checks

      # check e_ehsize
      if self.e_ehsize != (40 + 3 * self.sizeof_ptr):
         return False

      if self.e_shstrndx >= self.e_shnum:
         return False

      # check e_shentsize
      if self.e_shentsize != (16 + 6 * self.sizeof_ptr):
         return False

      # check e_phentsize
      if self.e_phentsize != (8 + 6 * self.sizeof_ptr):
         return False

      # Check that there is room for the phdr table
      if self.e_phoff > (len(self.raw) - self.e_phentsize * self.e_phnum):
         return False

      # Check that there is room for the shdr table
      if self.e_shoff > (len(self.raw) - self.e_shentsize * self.e_shnum):
         return False

      # many other checks we could perform
      return True

   def resolve_sym(self, symidx, addr):
      if symidx < len(self.symbols):
         sym = self.symbols[symidx]
         #print "Resolving symbol: %s" % sym.name
         self.add_symbol(addr, sym.name)
         if sym.type == STT_FUNC:
            self.add_import(addr, sym.name)

   def parse_rel(self, addr, size):
      if self.sizeof_ptr == 4:
         mask = 0xff
         shift = 8
      else:
         mask = 0xffffffff
         shift = 32
      relsz = 2 * self.sizeof_ptr
      num_rels = size // relsz
      for i in range(num_rels):
         r_offset = self.get_pointer(addr + i * relsz)
         r_info = self.get_pointer(addr + i * relsz + self.sizeof_ptr)
         r_sym = r_info >> shift
         r_type = r_info & mask
         #print "REL r_offset 0x%x" % r_offset
         self.resolve_sym(r_sym, r_offset)

   def parse_rela(self, addr, size):
      if self.sizeof_ptr == 4:
         mask = 0xff
         shift = 8
      else:
         mask = 0xffffffff
         shift = 32
      relsz = 3 * self.sizeof_ptr
      num_rels = size // relsz
      for i in range(num_rels):
         r_offset = self.get_pointer(addr + i * relsz)
         r_info = self.get_pointer(addr + i * relsz + self.sizeof_ptr)
         r_addend = self.get_pointer(addr + i * relsz + 2 * self.sizeof_ptr)
         r_sym = r_info >> shift
         r_type = r_info & mask
         #print "RELA r_offset 0x%x" % r_offset
         self.resolve_sym(r_sym, r_offset)

   def parse_imports(self):
      if self.dyn_hdr is None:
         return
      jmprel = None
      pltgot = None
      if DT_JMPREL in self.dyn_hdr.dyns:
         jmprel = self.dyn_hdr.dyns[DT_JMPREL]
         pltrelsz = self.dyn_hdr.dyns[DT_PLTRELSZ]
         pltrel = self.dyn_hdr.dyns[DT_PLTREL]
      if DT_PLTGOT in self.dyn_hdr.dyns:
         pltgot = self.dyn_hdr.dyns[DT_PLTGOT]

      if jmprel is not None:
         if pltrel == DT_REL:
            self.parse_rel(jmprel, pltrelsz)
         elif pltrel == DT_RELA:
            self.parse_rela(jmprel, pltrelsz)
         else:
            print "UNEXPECTED PLTREL value: %d" % pltrel

   def parse_symbols(self):
      symsz = 8 + 2 * self.sizeof_ptr
      for s in self.shdrs:
         if s.sh_type == SHT_SYMTAB or s.sh_type == SHT_DYNSYM:
            num_syms = s.sh_size // symsz
            #print "Section %s has %d symbols" % (s.name, num_syms)
            for i in range(num_syms):
               addr = s.sh_addr + i * symsz
               st_name = self.get_dword(addr)
               if self.sizeof_ptr == 4:
                  idx = 2
                  fields = struct.unpack(self.endian + "IIBBH", self.get_bytes(addr + 4, 12))
               else:
                  idx = 0
                  fields = struct.unpack(self.endian + "BBHQQ", self.get_bytes(addr + 4, 20))
               st_info = fields[idx]
               st_other = fields[idx + 1]
               st_shndx = fields[idx + 2]
               st_value = fields[(idx + 3) % 5]
               st_size = fields[(idx + 4) % 5]
               name = self.get_string(self.symbol_strtab + st_name)
               #print "Symbol name: %s" % name
               sym = ElfSymbol(name, st_value, st_size, st_info, st_other, st_shndx)
               self.symbols.append(sym)
               #if sym.type == STT_FUNC:
                  #print "Function symbol %s at address 0x%x" % (name, st_value)

   def parse_exports(self):
      self.add_export(self.start, "_start")
      # add DT_INIT == init_proc and DT_FINI == term_proc
      if self.dyn_hdr is not None:
         if DT_INIT in self.dyn_hdr.dyns:
            self.add_export(self.dyn_hdr.dyns[DT_INIT], ".init_proc")
         if DT_FINI in self.dyn_hdr.dyns:
            self.add_export(self.dyn_hdr.dyns[DT_FINI], ".term_proc")
      for sym in self.symbols:
         if sym.type == STT_FUNC and sym.value != 0:
            self.add_export(sym.value, sym.name)
      #for addr,name in self.exports_by_addr.iteritems():
         #print "EXPORT: 0x%x - %s" % (addr, name)

   def load_phdrs(self):
      self.dyn_hdr = None
      for i in range(self.e_phnum):
         phdr = ElfProgramHeader(self, self.e_phoff + self.e_phentsize * i)
         self.phdrs.append(phdr)
         if phdr.p_type == PT_DYNAMIC:
            self.dyn_hdr = phdr
         if phdr.p_type == PT_LOAD:
            va = phdr.p_vaddr
            if self.image_base is None or va < self.image_base:
               self.image_base = va
            mr = self.raw[phdr.p_offset:phdr.p_offset+phdr.p_filesz].ljust(phdr.p_memsz, '\x00')
            self.add_mapped(va, va + phdr.p_memsz, phdr.perms, mr)

   def load_shdrs(self):
      self.sections_by_name.clear()

      for i in range(self.e_shnum):
         shdr = ElfSectionHeader(self, self.e_shoff + self.e_shentsize * i)
         self.shdrs.append(shdr)
         if shdr.sh_type == SHT_STRTAB and i != self.e_shstrndx:
            self.symbol_strtab = shdr.sh_addr

      # now that we have sections, go back and pull section names
      # out of the sh names table
      strtab = self.shdrs[self.e_shstrndx]
      for s in self.shdrs:
         # defer setting the name until we are sure we know about the shstrtab
         s.name = strtab.get_string(s.sh_name)

         va = s.sh_addr
         # match perms against phdrs? sh_flags ??

         if (s.sh_flags & SHF_ALLOC) == 0:
            print 'Skipping section %s' % s.name
            continue
         self.add_section(s.name, va, va + s.sh_size, s.perms, s.sh_size)

   def load(self):
      if self.is_valid():
         del self.mapped[:]
         del self.sections[:]
         self.phdrs = []
         self.shdrs = []

         self.osabi = ord(self.raw[EI_OSABI])
         self.image_base = None   # set in load_phdrs
         self.start = self.e_entry

         self.load_phdrs()
         self.load_shdrs()

         # deal with dynamic section imports
         # deal with .got .plt
         # deal with exports
         # deal with symbol table
         # deal with dwarf and other debug info

         self.parse_symbols()
         self.parse_imports()
         self.parse_exports()
         return True
      return False

   def find_main(self, insts, to, frm):
      if self.arch != capstone.CS_ARCH_X86:
         return None
      addr = self.start
      if self.osabi != ELFOSABI_LINUX:
         #find main by scanning Linux start stup
         while addr in frm:
            inst = insts[addr]
            if inst.group(capstone.CS_GRP_JUMP):
               break
            xrefs = frm[addr]
            if inst.group(capstone.CS_GRP_CALL):
               for x in xrefs:
                  if x[1] == XR_CALL:
                     #call to libc_start_main
                     last = to[addr][0][0]
                     inst = insts[last]
                     main = inst.operands[-1].value.imm
                     return main
               break
            elif len(xrefs) == 1:
               if xrefs[0][1] == XR_FLOW:
                  addr = xrefs[0][0]
               else:
                  break
            else:
               break
      return None

class Elf32(ElfBase):

   def __init__(self, elf_file):
      ElfBase.__init__(self, elf_file)

   # override to perform file type validation checks such
   # as checking magic numbers, etc
   def is_valid(self):
#      try:
         if ord(self.raw[EI_CLASS]) != ELFCLASS32:
            return False
         self.set_pointer_size(4)
         if not ElfBase.is_valid(self):
            return False
         # now do Elf32 specific checks
         # following e_ident we have: self.endian + "HHIIIIIHHHHHH"
#      except Exception as e:
         #any exception means it's not a PE32
#         raise e
         return True

class Elf64(ElfBase):

   def __init__(self, elf_file):
      ElfBase.__init__(self, elf_file)

   # override to perform file type validation checks such
   # as checking magic numbers, etc
   def is_valid(self):
      try:
         if ord(self.raw[EI_CLASS]) != ELFCLASS64:
            return False
         self.set_pointer_size(8)
         if not ElfBase.is_valid(self):
            return False
         #now do Elf64 specific checks
         # following e_ident we have: self.endian + "HHIQQQIHHHHHH
      except Exception as e:
         #any exception means it's not a PE32
         raise e
#         return False
      return True
