#!/usr/bin/env python

'''
Crude PE32 / PE32+ loader, conforming to the Loader interface, for a stand-alone binnavi compatible disassembler
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

IMAGE_FILE_MACHINE_I386 = 0x14c
IMAGE_FILE_MACHINE_ARM = 0x1c0
IMAGE_FILE_MACHINE_THUMB = 0x1c2
IMAGE_FILE_MACHINE_ARMV7 = 0x1c4
IMAGE_FILE_MACHINE_AMD64 = 0x8664

OK_PE_MACHINES = [IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_ARM,
                  IMAGE_FILE_MACHINE_THUMB, IMAGE_FILE_MACHINE_ARMV7,
                  IMAGE_FILE_MACHINE_AMD64]

IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b
IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b

IMAGE_DOS_SIGNATURE = 0x5A4D
IMAGE_NT_SIGNATURE = 0x00004550

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000

DATA_DIRECTORY_EXPORT = 0
DATA_DIRECTORY_IMPORT = 1

class InvalidHeader(Exception):
   def __init__(self, msg):
      Exception.__init__(self, msg)

class FileHeader(object):

   def __init__(self, raw, offset):
      self.raw = raw[offset:offset+20]
      fields = struct.unpack("<HHIIIHH", self.raw)
      self.Machine = fields[0]
      self.NumberOfSections = fields[1]
      self.TimeDateStamp = fields[2]
      self.PointerToSymbolTable = fields[3]
      self.NumberOfSynbols = fields[4]
      self.SizeOfOptionalHeader = fields[5]
      self.Characteristics = fields[6]

   def __del__(self):
      del self.raw

   def sizeof(self):
      return len(self.raw)

class ImportDirectory(object):

   # enough loading has taken place by the time that we get here
   # that we need to start dealing with RVA
   def __init__(self, pe, va):
      self.raw = pe.get_bytes(va, 20)
      fields = struct.unpack("<IIIII", self.raw)
      self.ilt = fields[0]
      self.time_date = fields[1]
      self.forwarder = fields[2]
      self.name_rva = fields[3]
      self.iat = fields[4]
      self.pe = pe

   def __del__(self):
      del self.raw

   def parse(self):
      self.dll = self.pe.get_string(self.name_rva + self.pe.image_base)
      if self.ilt != 0:
         iat = self.ilt
      else:
         iat = self.iat
      mask = 0x80 << (self.pe.sizeof_ptr * 8 - 8)
      while True:
         addr = iat + self.pe.image_base
         iat += self.pe.sizeof_ptr
         ie = self.pe.get_pointer(addr)
         if ie == 0:
            break
         if ie & mask:
            # it's an ordinal
            func = "%s_%d" % (self.dll.replace('.', '_'), ie & 0xffff)
         else:
            # it's a name rva
            func = self.pe.get_string(ie + 2 + self.pe.image_base)
         self.pe.add_import(addr, func)

   def is_null_dir(self):
      return self.raw == ('\x00'*20)

class ExportDirectory(object):

   # enough loading has taken place by the time that we get here
   # that we need to start dealing with RVA
   def __init__(self, pe, va, size):
      self.raw = pe.get_bytes(va, 40)
      self.rva = va - pe.image_base
      self.end_rva = self.rva + size
      fields = struct.unpack("<7I", self.raw[12:])
      self.NameRva = fields[0]
      self.OrdinalBase = fields[1]
      self.NumberOfFunctions = fields[2]
      self.NumberOfNames = fields[3]
      self.AddressOfFunctions = fields[4]
      self.AddressOfNames = fields[5]
      self.AddressOfNameOrdinals = fields[6]
      self.pe = pe

   def __del__(self):
      del self.raw

   def parse(self):
      self.dll = self.pe.get_string(self.NameRva + self.pe.image_base)
      aof = self.AddressOfFunctions + self.pe.image_base
      aon = self.AddressOfNames + self.pe.image_base
      aono = self.AddressOfNameOrdinals + self.pe.image_base
      fcount = 0
      for f in range(self.NumberOfNames):
         name_rva = self.pe.get_dword(aon)
         aon += 4
         name = self.pe.get_string(name_rva + self.pe.image_base)
         func_idx = self.pe.get_word(aono + f * 2)
         func_rva = self.pe.get_dword(aof + func_idx * 4)
         if func_rva >= self.rva and func_rva < self.end_rva:
            #this is a forwarded entry
            fcount += 1
            continue
         else:
            self.pe.add_export(func_rva + self.pe.image_base, name)

      for f in range(self.NumberOfNames, self.NumberOfFunctions):
         name = "%s_%d" % (self.dll.replace('.', '_'), f)
         func_idx = self.pe.get_word(aono + f * 2)
         func_rva = self.pe.get_dword(aof + func_idx * 4)
         self.pe.add_export(func_rva + self.pe.image_base, name)

class OptionalHeaderBase(object):

   def __init__(self, raw, offset):
      try:
         self.common = raw[offset:offset+24]
         fields = struct.unpack("<HBBIIIII", self.common)
         self.Magic = fields[0]
         self.SizeOfCode = fields[3]
         self.SizeOfInitializedData = fields[4]
         self.SizeOfUninitializedData = fields[5]
         self.AddressOfEntryPoint = fields[6]
         self.BaseOfCode = fields[7]
         if self.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC:
            bod = raw[offset+24:offset+28]
            self.common += bod
            self.BaseOfData = struct.unpack("<I", bod)[0]
         self.DataDirectories = None
         self.ImageBase = 0
      except Exception as e:
         print e.message
         raise InvalidHeader("Invalid PE header")

   def __del__(self):
      del self.common

   # return va (not rva),size
   def get_directory(self, n):
      rva,size = struct.unpack("<II", self.DataDirectories[n * 8:8 + n * 8])
      if size == 0:
         return None, None
      return self.ImageBase + rva, size

class OptionalHeader32(OptionalHeaderBase):

   def __init__(self, raw, offset):
      OptionalHeaderBase.__init__(self, raw, offset)
      try:
         self.fields = raw[offset+28:offset+96]
         tmp = struct.unpack("<III", self.fields[0:12])
         self.ImageBase = tmp[0]
         self.SectionAlignment = tmp[1]
         self.FileAlignment = tmp[2]

         self.NumberOfRvaAndSizes = struct.unpack("<I", self.fields[-4:])[0]

         self.DataDirectories = raw[offset+96:offset+96+self.NumberOfRvaAndSizes*8]
      except Exception as e:
         print e.message
         raise InvalidHeader("Invalid PE32 header")

   def __del__(self):
      del self.fields
      del self.DataDirectories
      OptionalHeaderBase.__del__(self)

class OptionalHeader64(OptionalHeaderBase):

   def __init__(self, raw, offset):
      OptionalHeaderBase.__init__(self, raw, offset)
      try:
         self.fields = raw[offset+24:offset+112]

         tmp = struct.unpack("<QII", self.fields[0:16])
         self.ImageBase = tmp[0]
         self.SectionAlignment = tmp[1]
         self.FileAlignment = tmp[2]

         self.NumberOfRvaAndSizes = struct.unpack("<I", self.fields[-4:])[0]

         self.DataDirectories = raw[offset+112:offset+112+self.NumberOfRvaAndSizes*8]
      except Exception as e:
         raise InvalidHeader("Invalid PE64 header")

   def __del__(self):
      del self.fields
      del self.DataDirectories
      OptionalHeaderBase.__del__(self)

class SectionHeader(object):

   def __init__(self, raw, offset):
#      try:
         self.raw = raw[offset:offset+40]
         fields = struct.unpack("<8sIIIIIIHHI", self.raw)
         self.Name = fields[0].rstrip('\x00')
         self.VirtualSize = fields[1]
         self.VirtualAddress = fields[2]
         self.SizeOfRawData = fields[3]
         self.PointerToRawData = fields[4]
         self.PointerToRelocations = fields[5]
         self.PointerToLinenumbers = fields[6]
         self.NumberOfRelocations = fields[7]
         self.NumberOfLinenumbers = fields[8]
         self.Characteristics = fields[9]
         self.perms = 0
         if self.Characteristics & IMAGE_SCN_MEM_READ:
            self.perms |= PROT_READ
         if self.Characteristics & IMAGE_SCN_MEM_WRITE:
            self.perms |= PROT_WRITE
         if self.Characteristics & IMAGE_SCN_MEM_EXECUTE:
            self.perms |= PROT_EXEC
#      except:
#         raise InvalidHeader("Invalid section header")

   def __del__(self):
      del self.raw

class PeBase(Loader):

   def __init__(self, pe_file):
      Loader.__init__(self, pe_file)

      self.pe_offset = 0
      self.section_headers = []
      
      self.non_returning_funcs.append("ExitProcess")
      self.non_returning_funcs.append("ExitThread")
      self.non_returning_funcs.append("_ExitProcess")
      self.non_returning_funcs.append("_ExitThread")

   def __del__(self):
      del self.section_headers[:]
      del self.section_headers
      Loader.__del__(self)

   # Perform common PE validation tasks
   def is_valid(self):
      if self.raw[0:2] != 'MZ':
         return False
      # image sections are still in .raw mode at this point
      self.pe_offset = self.get_dword(0x3c)
      if self.get_dword(self.pe_offset) != IMAGE_NT_SIGNATURE:
         return False
      self.FileHeader = FileHeader(self.raw, self.pe_offset + 4)

      if self.FileHeader.Machine == IMAGE_FILE_MACHINE_I386:
         self.arch = capstone.CS_ARCH_X86
         self.mode = capstone.CS_MODE_32
         self.arch_name = 'x86-32'
      elif self.FileHeader.Machine == IMAGE_FILE_MACHINE_ARM or self.FileHeader.Machine == IMAGE_FILE_MACHINE_THUMB:
         self.arch = capstone.CS_ARCH_ARM
         self.mode = capstone.CS_MODE_ARM
         self.arch_name = 'ARM-32'
      elif self.FileHeader.Machine == IMAGE_FILE_MACHINE_ARMV7:
         self.arch = capstone.CS_ARCH_ARM
         self.mode = capstone.CS_MODE_THUMB
         self.arch_name = 'ARM-THUMB'
      elif self.FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64:
         self.arch = capstone.CS_ARCH_X86
         self.mode = capstone.CS_MODE_64
         self.arch_name = 'x86-64'
      else:
         # anything else, we don't recognize
         # could move this check into the caller
         # to allow it to determine whether it has an appropriate 
         # disassembler
         return False

      oh_magic = self.get_word(self.pe_offset + 24)
      if oh_magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC and oh_magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC:
         return False
      #many other checks we could perform
      return True

   def load_sections(self):
      del self.mapped[:]
      del self.sections[:]
      self.sections_by_name.clear()
      for i in range(self.FileHeader.NumberOfSections):
         self.section_headers.append(SectionHeader(self.raw, self.pe_offset + 24 + self.FileHeader.SizeOfOptionalHeader + i * 40))
      for s in self.section_headers:
         va = self.OptionalHeader.ImageBase + s.VirtualAddress
         mr = self.raw[s.PointerToRawData:s.PointerToRawData+s.SizeOfRawData].ljust(s.VirtualSize, '\x00')
         self.add_mapped(va, va + max(s.VirtualSize, s.SizeOfRawData), s.perms, mr)
         self.add_section(s.Name, va, va + s.VirtualSize, s.perms, s.SizeOfRawData)

   def parse_imports(self):
      va,size = self.OptionalHeader.get_directory(DATA_DIRECTORY_IMPORT)
      if size is not None:
         while True:
            id = ImportDirectory(self, va)
            if id.is_null_dir():
               break
            id.parse()
            va += 20

   def parse_symbols(self):
      pass

   def parse_exports(self):
      self.add_export(self.start, "_start")
      va,size = self.OptionalHeader.get_directory(DATA_DIRECTORY_EXPORT)
      if size is not None:
         exp = ExportDirectory(self, va, size)
         exp.parse()

   def load(self):
      if self.is_valid():
         self.image_base = self.OptionalHeader.ImageBase
         self.start = self.OptionalHeader.AddressOfEntryPoint + self.image_base
         self.load_sections()
         self.parse_imports()
         self.parse_exports()
         return True
      return False

class Pe32(PeBase):

   def __init__(self, pe_file):
      PeBase.__init__(self, pe_file)

   # override to perform file type validation checks such
   # as checking magic numbers, etc
   def is_valid(self):
      try:
         if not PeBase.is_valid(self):
            return False
         #now do PE32 specific checks
         self.OptionalHeader = OptionalHeader32(self.raw, self.pe_offset + 24)
         if self.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC:
            return False
         self.set_pointer_size(4)
      except Exception as e:
         #any exception means it's not a PE32
         raise e
#         return False
      return True

class Pe64(PeBase):

   def __init__(self, pe_file):
      PeBase.__init__(self, pe_file)

   # override to perform file type validation checks such
   # as checking magic numbers, etc
   def is_valid(self):
      try:
         if not PeBase.is_valid(self):
            return False
         #now do PE64 specific checks
         self.OptionalHeader = OptionalHeader64(self.raw, self.pe_offset + 24)
         if self.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC:
            return False
         self.set_pointer_size(8)
      except Exception as e:
         #any exception means it's not a PE32
         raise e
#         return False
      return True
