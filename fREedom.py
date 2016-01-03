#!/usr/bin/env python

'''
Stand-alone binnavi compatible disassembler based on capstone
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
import argparse
import capstone
import x86_disasm
import pe_loader
import elf_loader
import binnavi_db

class UnsupportedArch(Exception):
   def __init__(self, msg):
      Exception.__init__(self, msg)

class UnsupportedFormat(Exception):
   def __init__(self, msg):
      Exception.__init__(self,msg)

def main(args):

   # cycle through available loaders, if one matches
   # pass it into the disassembler
   ldr = pe_loader.Pe32(args.binary)
   if not ldr.load():
      del ldr
      ldr = pe_loader.Pe64(args.binary)
      if not ldr.load():
         del ldr
         ldr = elf_loader.Elf32(args.binary)
         if not ldr.load():
            del ldr
            ldr = elf_loader.Elf64(args.binary)
            if not ldr.load():
               del ldr
               raise UnsupportedFormat("Unsupported file format for %s" % args.binary)

   if ldr.arch == capstone.CS_ARCH_X86:
      dis = x86_disasm.x86_disasm(ldr)   
   else:
      raise UnsupportedArch("Unsupported processor architecture for %s" % args.binary)
   
   dis.generate_data()

   print "found %d instructions" % len(dis.visited)
   print "found %d basic blocks" % len(dis.basic_blocks)
   print "found %d functions" % len(dis.call_targets)

   '''
   print "Functions identified at:"
   dis.call_targets.sort()
   for c in dis.call_targets:
      print "   0x%x" % c
   '''

   #dis.print_disassembly()

   db = binnavi_db.binnavi_db(args.database, args.user, args.passwd, args.dbhost)
   db.export(dis)

# add argument parsing for database commection parameters
if __name__ == "__main__":
   parser = argparse.ArgumentParser(description='Export to binnavi.')
   parser.add_argument('--database', help='name of database to export to')
   parser.add_argument('--user', help='database user name')
   parser.add_argument('--pass', dest='passwd', help='database user password')
   parser.add_argument('--dbhost', help='database host name')
   parser.add_argument('--binary', type=str, required=False, help='binary file to export')
   parser.add_argument('--delete', action='store_true', required=False,
                       help='flag to initiate module deletion')
   parser.add_argument('--modules', type=int, nargs='+', required=False,
                      help='module numbers to delete')

   args = parser.parse_args()

   if args.delete:
      db = binnavi_db.binnavi_db(args.database, args.user, args.passwd, args.dbhost)
      for m in args.modules:
         db.delete_module(m)
   else:
      main(args)
