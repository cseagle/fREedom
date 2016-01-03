#!/usr/bin/env python

'''
Base class for loaders (file parsers) for a stand-alone binnavi compatible disassembler
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
import os

LITTLE_ENDIAN = '<'
BIG_ENDIAN    = '>'

PROT_READ =  1
PROT_WRITE = 2
PROT_EXEC =  4
PROT_ALL  = PROT_READ | PROT_WRITE | PROT_EXEC

class MappedRegion(object):
   def __init__(self, start, end, perms, raw):
      self.start = start
      self.end = end
      self.perms = perms
      self.raw = raw

   def contains(self, addr, blen = 1):
      _end = addr + blen
      return addr >= self.start and addr < self.end and _end <= self.end
      
   def get_bytes(self, addr, blen = 1):
      if self.contains(addr, blen):
         offset = addr - self.start
         return self.raw[offset:offset+blen]
      return None

class Section(object):
   def __init__(self, name, start, end, perms, filesz):
      self.name = name
      self.start = start
      self.end = end
      self.perms = perms
      self.filesz = filesz
      
      print "Created section %s, 0x%x:0x%x, raw length 0x%x, perms %d" % (self.name, self.start, self.end, filesz, self.perms)

   def contains(self, addr):
      return addr >= self.start and addr < self.end

   def get_raw_bytes(self, ldr):
      raw = ldr.get_bytes(self.start, self.filesz)
      if raw is None:
         sys.stderr.write("Failed to get raw content for section %s at address 0x%x for size 0x%s\n" % (self.name, self.start, self.filesz))
      return ldr.get_bytes(self.start, self.filesz)

class Loader(object):

   def __init__(self, fname):
      self.exe = fname
      f = open(fname, 'rb')
      self.raw = f.read()
      self.md5 = hashlib.md5(self.raw).hexdigest()
      self.sha1 = hashlib.sha1(self.raw).hexdigest()
      f.close()

      self.name = os.path.basename(fname)

      self.image_base = 0
      self.start = 0

      self.sections = []           # Section
      self.sections_by_name = {}   # str:Section
      self.imports_by_name = {}    # str:int
      self.imports_by_addr = {}    # int:str
      self.exports_by_addr = {}    # int:str

      self.symbols_by_addr = {}    # int:str
      self.symbols_by_name = {}    # str:int
      self.mapped = []             # MappedRegion

      self.non_returning_funcs = []

      self.add_mapped(0, len(self.raw), PROT_ALL, self.raw)

      self.set_endianness(LITTLE_ENDIAN)
      self.sizeof_ptr = 4
      self.arch = None
      self.mode = None
      self.cached_section = None
      self.cached_region = None

   def __del__(self):
      del self.mapped[:]
      del self.sections[:]
      del self.sections
      del self.raw
      del self.name
      self.sections_by_name.clear()
      self.imports_by_name.clear()
      self.imports_by_addr.clear()
      self.exports_by_addr.clear()
      self.symbols_by_name.clear()
      self.symbols_by_addr.clear()

   def set_endianness(self, which_endian):
      self.endian = which_endian

   def set_pointer_size(self, sizeof_ptr):
      self.sizeof_ptr = sizeof_ptr

   # override to create a mapped process binary image where
   # raw does not match the memory layout of the running
   # process.
   def load(self):
      # probably want to start with:
      # del sections[:]
      # sections_by_name.clear()
      pass

   def get_mapped(self, addr):
      if self.cached_region is not None and self.cached_region.contains(addr):
         return self.cached_region
      for m in self.mapped:
         if m.contains(addr):
            self.cached_region = m
            return m
      return None

   #regions should not overlap!
   def add_mapped(self, start, end, perms, raw):
      self.mapped.append(MappedRegion(start, end, perms, raw))

   def del_mapped(self, start):
      rem = None
      for m in self.mapped:
         if m.start == addr:
            if self.cached_region == m:
               self.cached_region = None
            rem = m
            break
      if rem is not None:
         self.mapped.remove(rem)
         del rem

   # override to perform file type validation checks such
   # as checking magic numbers, etc
   def is_valid(self):
      return True

   def get_bytes(self, addr, len):
      m = self.get_mapped(addr)
      if m is not None:
         return m.get_bytes(addr, len)
      return None

   def get_byte(self, addr):
      return self.get_bytes(addr, 1)

   def get_word(self, addr):
      return struct.unpack(self.endian + "H", self.get_bytes(addr, 2))[0]

   def get_dword(self, addr):
      try:
	 return struct.unpack(self.endian + "I", self.get_bytes(addr, 4))[0]
      except Exception, e:
         print "Unable to read dword from address 0x%x" % addr
         raise e

   def get_qword(self, addr):
      return struct.unpack(self.endian + "Q", self.get_bytes(addr, 8))[0]

   def get_pointer(self, addr):
      if self.sizeof_ptr == 4:
         return self.get_dword(addr)
      elif self.sizeof_ptr == 8:
         return self.get_qword(addr)

   def get_string(self, addr):
      res = ''
      while True:
         ch = self.get_byte(addr)
         if ch == '\x00':
            break
         addr += 1
         res += ch
      return res

   # get containing section for given address
   def get_section(self, addr):
      if self.cached_section is not None and self.cached_section.contains(addr):
         return self.cached_section
      for s in self.sections:
         if s.contains(addr):
            self.cached_section = s
            return s
      return None

   def add_section(self, name, start, end, perms, filesz):
      sect = Section(name, start, end, perms, filesz)
      self.sections.append(sect)
      self.sections_by_name[name] = sect

   def add_import(self, addr, name):
      self.imports_by_addr[addr] = name
      self.imports_by_name[name] = addr

   def add_symbol(self, addr, name):
      self.symbols_by_addr[addr] = name
      self.symbols_by_name[name] = addr

   def add_export(self, addr, name):
      self.exports_by_addr[addr] = name
      
   #override in subclasses if you have an algorithm
   #for finding main given the address of start
   #and all currently known instructions
   def find_main(self, insts, to, frm):
      return None

