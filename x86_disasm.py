#!/usr/bin/env python

'''
An x86/X64 disassembly module for a stand-alone binnavi compatible disassembler
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
import binascii
import psycopg2
import capstone
import capstone.x86_const
import pe_loader
import elf_loader
import binnavi_db
from bn_disasm import *

'''
TODO
   resolve switch table jumps
   find virtual functions
   locate unfound instruction bytes
   identify thunk functions and what they thunk to
   figure out how expression_substitutions work
   figure out when 'symbol' field in expression_nodes is used
   get address_references working
   build stack_frames
'''

def signed_byte(b):
   if b & 0x80:
      return -(256 - b)
   return b

def signed_dword(d):
   val = unsigned_dword(d)
   if val & 0x80000000:
      return -(0x100000000 - val)
   return val

def unsigned_dword(d):
   val = 0
   shift = 0
   for b in d:
      val = val + (b << shift)
      shift += 8
   return val

def tostr(inst):
   res = ''
   for b in inst.bytes:
      res += chr(b)
   return binascii.hexlify(res)

class x86_disasm(Disassembly):

   def __init__(self, loader):
      Disassembly.__init__(self, loader)

      self.dis = capstone.Cs(loader.arch, loader.mode)
      self.dis.detail = True

      for addr,name in self.loader.exports_by_addr.iteritems():
         self.names[addr] = name
         if self.is_possible_code(addr):
            self.locs.append(addr)
            self.call_targets.add(addr)
            if addr != 0:
               #treat address zero differently, don't add xrefs to it
               self.add_basic_block_start(addr)

      if loader.mode == capstone.CS_MODE_32 and loader.arch == capstone.CS_ARCH_X86:
         self.func_sigs.append("\x8b\xff\x55\x8b\xec")
         self.func_sigs.append("\x55\x8b\xec")

   def get_dword(self, addr):
      return self.loader.get_dword(addr)

   def get_qword(self, addr):
      return self.loader.get_qword(addr)

   def get_pointer(self, addr):
      return self.loader.get_pointer(addr)

   def scan_data(self):
      for s in self.loader.sections:
         if s.name == ".rdata":
            ptr_mask = ~(self.loader.sizeof_ptr - 1)
            for addr in range(s.start, s.end & ptr_mask, self.loader.sizeof_ptr):
               val = self.get_pointer(addr)
               if val is None:
                  break
               if self.is_possible_code(val) and val not in self.visited:
                  self.locs.append(val)

   def get_op_name(self, addr, default):
      if addr in self.xrefs_from:
         refs = self.xrefs_from[addr]
         for r in refs:
            if r[1] != XR_FLOW:   # this is a jump or call
               if r[0] in self.loader.imports_by_addr:
                  return self.loader.imports_by_addr[r[0]]
               return self.names[r[0]]
      return default

   def resolve_thunk(self, addr):
      if addr in self.loader.imports_by_addr:
         return self.loader.imports_by_addr[addr]
      return ''

   def add_xref(self, frm, to, xr_type=XR_FLOW):
      if frm not in self.xrefs_from:
         self.xrefs_from[frm] = []
      self.xrefs_from[frm].append((to, xr_type))
      from_list = self.xrefs_from[frm]
      if len(from_list) >= 2 and not self.is_returning_call(from_list):
         # add all destinations to basic_blocks
         for xr in from_list:
            if xr[0] != 0:
               #treat address zero differently, don't add xrefs to it
               self.add_basic_block_start(xr[0])
      
      if to not in self.xrefs_to:
         self.xrefs_to[to] = []
      self.xrefs_to[to].append((frm, xr_type))
      to_list = self.xrefs_to[to]
      if to not in self.names:
         if xr_type == XR_CALL:
            self.names[to] = 'sub_%x' % to
         elif xr_type >= XR_JUMP:  # JUMP or JCC
            self.names[to] = 'loc_%x' % to
         self.add_loc(to)
      elif xr_type == XR_CALL and self.names[to] == ('loc_%x' % to):
         #update loc_ label to sub_ label now that a call was found 
         self.names[to] = 'sub_%x' % to
      if to not in self.basic_blocks:
         if xr_type == XR_CALL or len(to_list) > 1:
            if to != 0:
               #treat address zero differently, don't add xrefs to it
               self.add_basic_block_start(to)

   #add an address we need to explore
   def add_loc(self, addr):
      if addr in self.visited:
         return
      self.locs.append(addr)

   def is_conditional(self, i):
      op = i.bytes[0]
      if (op >= 0x70 and op <= 0x7f) or (op >= 0xe0 and op <= 0xe3):
         return True
      elif op == 0x0f:
         op2 = i.bytes[1]
         if op2 >= 0x80 and op2 <= 0x8f:
            return True
      return False

   def process_jump(self, i):
      opcode = i.bytes[0]
      offset = signed_byte(i.bytes[1])
      short_tgt = i.address + i.size + offset
      if opcode == 0xeb:   # jmp disp8
         self.add_xref(i.address, short_tgt, XR_JUMP)
         self.jmp_targets.add(short_tgt)
         return True
      if opcode == 0xe9:   # jmp disp32
         offset = signed_dword(i.bytes[1:5])
         tgt = i.address + i.size + offset
         self.add_xref(i.address, tgt, XR_JUMP)
         self.jmp_targets.add(tgt)
         return True
      if (opcode >= 0x70 and opcode <= 0x7f) or opcode == 0xe3: # jcc jecx disp8
         self.add_xref(i.address, short_tgt, XR_JCC)
         self.jmp_targets.add(short_tgt)
         return False
      elif opcode == 0x0f:  # jcc disp32
         op2 = i.bytes[1]
         if op2 >= 0x80 and op2 <= 0x8f:
            offset = signed_dword(i.bytes[2:6])
            tgt = i.address + i.size + offset
            self.add_xref(i.address, tgt, XR_JCC)
            self.jmp_targets.add(tgt)
            return False
#         else:
#            sys.stderr.write("Classified jump (0x0f), not categorized at address 0x%x: %s\n" % (i.address, tostr(i)))
      elif opcode == 0xff:
         modrm = i.modrm   # i.bytes[1]
         if modrm == 0x25: #near jump [disp]
            slot = unsigned_dword(i.bytes[2:6])
            if i.address in self.loader.imports_by_addr: #this is a thunk  DO BETTER HERE
               self.thunks.add(i.address)
               self.names[i.address] = self.loader.imports_by_addr[i.address]
#         else:
#            sys.stderr.write("Classified jump (0xff), not categorized at address 0x%x: %s\n" % (i.address, tostr(i)))
         return True
#      else:
#         sys.stderr.write("Classified jump, not categorized at address 0x%x: %s\n" % (i.address, tostr(i)))
      return True

   def process_call(self, i):
      opcode = i.bytes[0]
      if opcode == 0xe8:   # call disp32
         offset = signed_dword(i.bytes[1:5])
         tgt = i.address + i.size + offset
         self.call_targets.add(tgt)
         self.add_xref(i.address, tgt, XR_CALL)
         #add a minimal stack frame for this function, it will have at least a
         #return address
         #self.add_type("__SF%x" % tgt, self.loader.sizeof_ptr, None, False, STRUCT)
         return tgt in self.names and self.names[tgt] in self.loader.non_returning_funcs
      elif opcode == 0xff:
         modrm = i.modrm   # i.bytes[1]
         if modrm == 0x15: #near call [disp]
            slot = unsigned_dword(i.bytes[2:6])
            #sometimes this will be an imported function other times not
            #only xref that is really taking place here is a data reference
            #self.add_xref(i.address, slot, XR_CALL)
#         else:
#            sys.stderr.write("Classified call (0xff), not categorized at address 0x%x: %s\n" % (i.address, tostr(i)))
#      else:
#         sys.stderr.write("Classified call, not categorized at address 0x%x: %s\n" % (i.address, tostr(i)))
      #assume all calls return
      return False

   def add_address_ref(self, inst, opnum, node_id, aref_addr, false_id):
      is_jump = inst.group(capstone.CS_GRP_JUMP)
      is_call = inst.group(capstone.CS_GRP_CALL)
      if inst.operands[opnum].type == capstone.x86_const.X86_OP_IMM:
         if is_jump:
            if self.is_conditional(inst):
               self.arefs.append(AddressRef(inst.address, opnum, node_id, aref_addr, CONDITION_TRUE))
               self.arefs.append(AddressRef(inst.address, opnum, false_id, inst.address + inst.size, CONDITION_FALSE))
            else:
               self.arefs.append(AddressRef(inst.address, opnum, node_id, aref_addr, UNCONDITIONAL))
         elif is_call:
            self.arefs.append(AddressRef(inst.address, opnum, node_id, aref_addr, CALL_DIRECT))
         else:
            #raw data, aref_addr is an offset
            pass
      elif inst.operands[opnum].type == capstone.x86_const.X86_OP_MEM:
         if is_jump:
            dest = self.get_pointer(aref_addr)
            #try to determine whether this is a switch table
            if dest is not None and self.is_possible_code(dest):
               self.arefs.append(AddressRef(inst.address, opnum, node_id, dest, UNCONDITIONAL))
         elif is_call:
            dest = self.get_pointer(aref_addr)
            #try to determine whether this is a switch table
            if dest is not None and self.is_possible_code(dest):
               self.arefs.append(AddressRef(inst.address, opnum, node_id, dest, CALL_INDIRECT))
         else:
            #raw data, aref_addr is a pointer
            #could check content at aref_addr to see if its a string
            self.arefs.append(AddressRef(inst.address, opnum, node_id, aref_addr, DATA))

   #THIS IS HIGHLY ARCHITECTURE DEPENDENT
   def process_operands(self, inst):
      opnum = 0
      #annotate the CsInsn with the operands we build here
      op_exprs = []
      for op in inst.operands:
         add_aref = False
         aref_addr = 0
         aref_op = 0
         aref_type = -1
         op_size = 'b%d' % op.size
         tree = []
         tree.append(OpNode(SIZE_PREFIX, op_size))
         if op.type == capstone.x86_const.X86_OP_REG:
            reg = inst.reg_name(op.reg)
            #operand expr is: op_size reg
            tree.append(OpNode(REGISTER, reg))
         elif op.type == capstone.x86_const.X86_OP_IMM:
            imm = op.imm
            #operand expr is: op_size imm
            tree.append(OpNode(IMMEDIATE_INT, imm))
            s = self.loader.get_section(imm)
            if s is not None:
               #immediate refers to a memory address
               #let's add an AddressRef
               add_aref = True
               aref_op = 1
               aref_addr = imm
         elif op.type == capstone.x86_const.X86_OP_MEM:
            if op.mem.segment == capstone.x86_const.X86_REG_INVALID:
               op_seg = None
            else:
               op_seg = '%s:' % inst.reg_name(op.mem.segment)
               tree.append(OpNode(OPERATOR + 10, op_seg))  # 10 = unary operator

            op_disp = op.mem.disp
            tree.append(OpNode(DEREFERENCE, '['))
            s = self.loader.get_section(op_disp)
            if s is not None:
               #immediate refers to a memory address
               #let's add an AddressRef
               add_aref = True
               aref_addr = op_disp

            if op.mem.base != capstone.x86_const.X86_REG_INVALID:   #has a base reg
               op_base = inst.reg_name(op.mem.base)
               if op.mem.index != capstone.x86_const.X86_REG_INVALID:   #has an index reg
                  op_scale = op.mem.scale
                  op_index = inst.reg_name(op.mem.index)
                  tree.append(OpNode(OPERATOR + 20, '+'))  # 20 = unary operator
                  tree.append(OpNode(REGISTER, op_base))
                  if op_scale == 1:
                     if op_disp == 0:
                        #operand expr is: op_size op_seg [ + op_base op_index
                        tree.append(OpNode(REGISTER, op_index))
                     else:
                        #operand expr is: op_size op_seg [ + op_base + op_index op_disp
                        tree.append(OpNode(OPERATOR + 20, '+'))  # 20 = unary operator
                        tree.append(OpNode(REGISTER, op_index))
                        aref_op = len(tree)
                        tree.append(OpNode(IMMEDIATE_INT, op_disp))
                  else:
                     if op_disp == 0:
                        #operand expr is: op_size op_seg [ + op_base * op_index op_scale
                        tree.append(OpNode(OPERATOR + 20, '*'))  # 20 = unary operator
                        tree.append(OpNode(REGISTER, op_index))
                        tree.append(OpNode(IMMEDIATE_INT, op_scale))
                     else:
                        #operand expr is: op_size op_seg [ + op_base + * op_index op_scale op_disp
                        tree.append(OpNode(OPERATOR + 20, '+'))  # 20 = unary operator
                        tree.append(OpNode(OPERATOR + 20, '*'))  # 20 = unary operator
                        tree.append(OpNode(REGISTER, op_index))
                        tree.append(OpNode(IMMEDIATE_INT, op_scale))
                        aref_op = len(tree)
                        tree.append(OpNode(IMMEDIATE_INT, op_disp))
               else:
                  if op_disp == 0:
                     #operand expr is: op_size op_seg [ op_base
                     tree.append(OpNode(REGISTER, op_base))
                  else:
                     #operand expr is: op_size op_seg [ + op_base op_disp
                     tree.append(OpNode(OPERATOR + 20, '+'))  # 20 = unary operator
                     tree.append(OpNode(REGISTER, op_base))
                     aref_op = len(tree)
                     tree.append(OpNode(IMMEDIATE_INT, op_disp))
            elif op.mem.index != capstone.x86_const.X86_REG_INVALID:   #has an index reg
               op_scale = op.mem.scale
               op_index = inst.reg_name(op.mem.index)
               if op_scale == 1:
                  if op_disp == 0:
                     #operand expr is: op_size op_seg [ op_index
                     tree.append(OpNode(REGISTER, op_index))
                  else:
                     #operand expr is: op_size op_seg [ + op_index op_disp
                     tree.append(OpNode(OPERATOR + 20, '+'))  # 20 = unary operator
                     tree.append(OpNode(REGISTER, op_index))
                     aref_op = len(tree)
                     tree.append(OpNode(IMMEDIATE_INT, op_disp))
               else:
                  if op_disp == 0:
                     #operand expr is: op_size op_seg [ * op_index op_scale
                     tree.append(OpNode(OPERATOR + 20, '*'))  # 20 = unary operator
                     tree.append(OpNode(REGISTER, op_index))
                     tree.append(OpNode(IMMEDIATE_INT, op_scale))
                  else:
                     #operand expr is: op_size op_seg [ + * op_index op_scale op_disp
                     tree.append(OpNode(OPERATOR + 20, '+'))  # 20 = unary operator
                     tree.append(OpNode(OPERATOR + 20, '*'))  # 20 = unary operator
                     tree.append(OpNode(REGISTER, op_index))
                     tree.append(OpNode(IMMEDIATE_INT, op_scale))
                     aref_op = len(tree)
                     tree.append(OpNode(IMMEDIATE_INT, op_disp))
            else:  #must be [disp] only, mem with no registers
               #operand expr is: op_size op_seg [ op_disp
               aref_op = len(tree)
               tree.append(OpNode(IMMEDIATE_INT, op_disp))
         elif op.type == capstone.x86_const.X86_OP_FP:
            sys.stderr.write("found an FP operand at 0x%x, op %d\n" % (inst.address, opnum))
         else:
            sys.stderr.write("Unknown operand at 0x%x, op %d\n" % (inst.address, opnum))
         # store operand expression tree for inst.addr, opnum
         if len(tree) > 0:
            expr = self.add_expr_tree(tree)
            if expr != 0:
               op_exprs.append(expr)
               if add_aref:
                  self.add_address_ref(inst, opnum, tree[aref_op].node_id, aref_addr, tree[0].node_id)
         opnum += 1
      self.operands[inst.address] = op_exprs

   def scan_gap_data(self):
      ptr_sz = self.loader.sizeof_ptr

      keylist = [a for a in self.visited]
      keylist.sort()
      last = None
      count = 0
      for a in keylist:
         i = self.insts[a]
         if last is not None and (last.address + last.size) != a:
            gap_start = last.address + last.size
            #round up to ptr aligned address
            gap_start = (gap_start + ptr_sz - 1) & ~(ptr_sz - 1)
            if gap_start >= a:
               continue
            for addr in range(gap_start, a, ptr_sz):
               val = self.get_pointer(addr)
               if val is None:
                  break
               if self.is_possible_code(val) and val not in self.visited:
                  self.locs.append(val)
                  #print "Adding text ptr 0x%x" % val
                  count += 1
         last = i
      #print "Gap data analysis added %d new locations" % count


def main(exe_file):
   ldr = pe_loader.Pe32(exe_file)
   if not ldr.load():
      del ldr
      ldr = pe_loader.Pe64(exe_file)
      if not ldr.load():
         del ldr
         ldr = elf_loader.Elf32(exe_file)
         if not ldr.load():
            del ldr
            ldr = elf_loader.Elf64(exe_file)
            if not ldr.load():
               del ldr
               print "Failed to recognize input file type"
               return

   dis = x86_disasm(ldr)
   print "starting with %d initial locations" % len(dis.locs)
   dis.generate_data()

   print "found %d instructions" % len(dis.visited)

   '''
   print "Functions identified at:"
   dis.call_targets.sort()
   for c in dis.call_targets:
      print "   0x%x" % c
   '''

   dis.print_disassembly()

if __name__ == "__main__":
   main(sys.argv[1])
