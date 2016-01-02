#!/usr/bin/env python

'''
The disassembly engine for a stand-alone binnavi compatible disassembler
'''

__author__ = "Chris Eagle"
__copyright__ = "Copyright 2015, Chris Eagle"
__credits__ = ["Chris Eagle"]
__license__ = "GPL"
__version__ = "2.0"
__maintainer__ = "Chris Eagle"
__email__ = "cseagle@gmail.com"
__status__ = "Use at your own risk"

import os
import hashlib
import sys
import capstone
import loader

XR_FLOW = 1
XR_CALL = 2
XR_JUMP = 3
XR_JCC  = 4

CONDITION_TRUE = 0
CONDITION_FALSE = 1
UNCONDITIONAL = 2
SWITCH        = 3
CALL_DIRECT   = 4
CALL_INDIRECT = 5
CALL_VIRTUAL  = 6
DATA          = 7
DATA_STRING   = 8

AREF_TYPES = {
   0:'conditional_true',
   1:'conditional_false',  
   2:'unconditional',
   3:'switch',
   4:'call_direct',
   5:'call_indirect',
   6:'call_virtual',
   7:'data',
   8:'data_string'
}

PERMISSIONS = {
  1:'READ',
  2:'WRITE',
  4:'EXECUTE',
  3:'READ_WRITE',
  5:'READ_EXECUTE',
  6:'WRITE_EXECUTE',
  7:'READ_WRITE_EXECUTE'
}

NO_TYPE = 0
SYMBOL = 1           # String to be displayed.
IMMEDIATE_INT = 2
IMMEDIATE_FLOAT = 3
OPERATOR = 4         # '+', '*' etc.
REGISTER = 5
SIZE_PREFIX = 6     # 'B4, 'B8', etc.
DEREFERENCE = 7

ATOMIC  = 0
POINTER = 1
ARRAY   = 2
STRUCT  = 3
UNION   = 4
FUNCTION_POINTER = 5

TYPE_CATEGORIES = {
  0:'atomic',
  1:'pointer',
  2:'array',
  3:'struct',
  4:'union',
  5:'function_pointer',
}

#do the xrefs in the given list describe a conditional jump
def is_conditional(xrefs):
   if len(xrefs) != 2:
      return False
   return (xrefs[0][1] == XR_JCC or xrefs[1][1] == XR_JCC)

# return as (False target, True target)
def get_conditional_targets(xrefs):
   if len(xrefs) != 2:
      return None
   if xrefs[0][1] == XR_FLOW:
      return (xrefs[0][0], xrefs[1][0])
   return (xrefs[1][0], xrefs[0][0])

# return as (return target, call target)
def get_call_targets(xrefs):
   if len(xrefs) != 2:
      return None
   if xrefs[0][1] == XR_FLOW:
      return (xrefs[0][0], xrefs[1][0])
   return (xrefs[1][0], xrefs[0][0])

class OpNode(object):

   def __init__(self, op_type, value):
      self.op_type = op_type
      self.value = value
      self.node_id = 0
      self.pos = 0

class Operand(object):

   def __init__(self, addr, expr, pos):
      self.addr = addr
      self.expr = expr
      self.pos = pos

class AddressRef(object):
   
   def __init__(self, addr, pos, node_id, dest, rtype):
      self.addr = addr
      self.pos = pos
      self.node_id = node_id
      self.dest = dest
      self.rtype = rtype

class TypeInfo(object):

   def __init__(self, id, name, size, pointer, signed, category):
      self.id = id
      self.name = name
      self.size = size
      self.pointer = pointer
      self.signed = signed
      self.category = category

class BlockInfo(object):
   def __init__(self, bid, seq, func_addr):
      self.bid = bid
      self.seq = seq
      self.func = func_addr

#callgraph edge
class CG_Edge(object):
   def __init__(self, src_func, src_bb, src_addr, dest):
      self.src_func = src_func
      self.src_bb = src_bb
      self.src_addr = src_addr
      self.dest = dest

#control flow graph edge
class CFG_Edge(object):
   def __init__(self, parent_func, src_bb, dest_bb, edge_type):
      self.parent_func = parent_func
      self.src_bb = src_bb
      self.dest_bb = dest_bb
      self.edge_type = edge_type

class Disassembly(object):

   def __init__(self, loader):
      self.loader = loader

      self.comment = ''

      self.locs = []             # addr - to be visited
      self.visited = set()       # addr - instructions we have actually examined
      self.insts = {}            # addr:cs.CsInsn - cache of disassemled instructions
      self.names = {}            # addr:string
      self.jmp_targets = set()   # addr
      self.call_targets = set()  # addr
      self.xrefs_to = {}         # addr:list of (int,int)  (addr,type)
      self.xrefs_from = {}       # addr:list of (int,int)  (addr,type)
      self.thunks = set()        # addr

      self.bb_id = 0
      self.basic_block_starts = set()     # star address for basic blocks
      self.basic_blocks = {}     # addr:(int, set)  block_start:[(block_id, parent funcs)]

      self.callgraph = []        # CG_Edge
      self.cfg = []              # CFG_Edge

      self.nodes = {}            # {str:tuple}   tuple is node,{str:tuple}
      self.exprs = {}            # int:[]    int expression_id, list of nodes in expression
      self.expr_strings = {}     # string representations of expressions : expr_id
      self.node_id = 0
      self.expr_id = 0
      self.operands = {}         # addr:[int]   instruction address -> list of operand expressions
      self.arefs = []            # AddressRef
      self.type_id = 0
      self.types = {}            # name:TypeInfo
      self.func_sigs = []        # str - list of function header signatures for signature matching
      self.data_locs = {}        # {addr:size} - locations known to be data and their sizes
      
      #these should really come from disassembly process ??
      #rather than just priming the pump here
      self.add_type("char", 8, None, True, ATOMIC)
      self.add_type("short", 16, None, True, ATOMIC)
      self.add_type("int", 32, None, True, ATOMIC)
      self.add_type("BYTE", 8, None, True, ATOMIC)
      self.add_type("WORD", 16, None, True, ATOMIC)
      self.add_type("DWORD", 32, None, True, ATOMIC)
      self.add_type("QWORD", 32, None, True, ATOMIC)
      self.add_type("int8_t", 8, None, True, ATOMIC)
      self.add_type("int16_t", 16, None, True, ATOMIC)
      self.add_type("int32_t", 32, None, True, ATOMIC)
      self.add_type("int64_t", 64, None, True, ATOMIC)
      self.add_type("uint8_t", 8, None, False, ATOMIC)
      self.add_type("uint16_t", 16, None, False, ATOMIC)
      self.add_type("uint32_t", 32, None, False, ATOMIC)
      self.add_type("uint64_t", 64, None, False, ATOMIC)

      for addr in loader.imports_by_addr:
         self.data_locs[addr] = loader.sizeof_ptr

   #do the xrefs in the given list describe a function call that returns
   def is_returning_call(self, xrefs):
      if len(xrefs) != 2:
         return False
      if xrefs[1][1] == XR_CALL:
         tgt = xrefs[1][0]
      elif xrefs[0][1] == XR_CALL:
         tgt = xrefs[0][0]
      else:
         return False   # not a call
      if tgt in self.names and self.names[tgt] in self.loader.non_returning_funcs:
         return False
      return (xrefs[0][1] == XR_FLOW and xrefs[1][1] == XR_CALL) or \
             (xrefs[1][1] == XR_FLOW and xrefs[0][1] == XR_CALL)

   def add_type(self, name, size, pointer, signed, category):
      self.type_id += 1
      self.types[name] = TypeInfo(self.type_id, name, size, pointer, signed, category)

   def add_basic_block_start(self, addr):
      self.basic_block_starts.add(addr)

   #returns new basic block id
   def add_basic_block(self, addr, parent):
      if addr not in self.basic_block_starts:
         return
      self.bb_id += 1
      if addr not in self.basic_blocks:
         self.basic_blocks[addr] = []
      bb = (self.bb_id, parent)
      self.basic_blocks[addr].append(bb)
      return bb[0]

   def is_bb_start(self, addr):
      return addr in self.basic_block_starts

   def get_bb_id(self, func, addr):
      inst = self.insts[addr]
      if hasattr(inst, "bb"):
         for block in inst.bb:
            if func == block.func:
               return block.bid
         '''
         sys.stderr.write("Unable to get_bb_id for 0x%x in func 0x%x\n" % (addr, func))
         for block in inst.bb:
            sys.stderr.write("(%d, %d, 0x%x), " % (block.bid, block.seq, block.func))
         sys.stderr.write("\n")
         '''
      '''
      else:
         sys.stderr.write("0x%x has no bb attr\n" % addr)
         sys.stderr.write("Unable to get_bb_id for 0x%x in func 0x%x\n" % (addr, func))
      '''
      return -1

   def print_func_owners(self, addr):
      insn = self.insts[addr]
      if hasattr(insn, "bb"):
         for b in insn.bb:
            sys.stderr.write("0x%x, " % b.func)
         sys.stderr.write("\n")
            

   def build_cfg(self):
      for addr,bb in self.basic_blocks.iteritems():
         if addr in self.call_targets:
            continue
         if addr in self.xrefs_to:
            #look at the instructions that refer to this basic block start address
            for xr in self.xrefs_to[addr]:
               src = xr[0]
               #add an edge for each block that the referring instruction belongs to
               for block in bb:
                  src_bb = self.get_bb_id(block[1], src)
                  if src_bb == -1:
                     # this seems to happen when we don't have a complete understanding
                     # of whether a function call fails to return or not
                     # which leads to the incorrect conclusion that the instruction
                     # following the call is reachable
                     '''
                     sys.stderr.write("0x%x refers to 0x%x but failed to find bid for 0x%x\n" % (src, addr, src))
                     sys.stderr.write("0x%x belongs to: " % src)
                     self.print_func_owners(src)
                     sys.stderr.write("0x%x belongs to: " % addr)
                     self.print_func_owners(addr)
                     '''
                     continue
                  xr_type = CONDITION_FALSE
                  if xr[1] == XR_FLOW:
                     if len(self.xrefs_from[src]) == 1:
                        xr_type = UNCONDITIONAL
                     else:
                        xr_type = CONDITION_FALSE
                  elif xr[1] == XR_JCC:
                     xr_type = CONDITION_TRUE
                  elif xr[1] == XR_JUMP:
                     xr_type = UNCONDITIONAL
                  else:  #should not get here
                     continue
                  edge = CFG_Edge(block[1], src_bb, block[0], xr_type)
                  self.cfg.append(edge)

   def build_callgraph(self):
      for func in self.call_targets:
         if func in self.xrefs_to:
            for xr in self.xrefs_to[func]:
               src = xr[0]
               inst = self.insts[src]
               if hasattr(inst, "bb"):
                  for block in inst.bb:
                     edge = CG_Edge(block.func, block.bid, src, func)
                     self.callgraph.append(edge)

   #need to traverse to figure out the parent functions for 
   #all basic blocks. Note we have more work to do than we should
   #this is a result of the binnavi database schema failing to actually
   #set the ex_N_basic_blocks primary key to (id, parent_function) as they 
   #claim to in
   #binnavi/src/main/java/com/google/security/zynamics/binnavi/manual/html/dbformat.htm
   #instead they only use id so we need a unique id when a block is part of more than
   #one function
   def extract_basic_block_data(self, func, addr, func_insts):
      bb = -1
      while True:
         if addr in func_insts:
            break
         func_insts.add(addr)
         if self.is_bb_start(addr):
            bb = self.add_basic_block(addr, func)
         if addr in self.xrefs_from:
            flows_to = -1
            xrefs = self.xrefs_from[addr]
            for xr in xrefs:
               if xr[1] == XR_FLOW:
                  flows_to = xr[0]
               elif xr[1] == XR_CALL:
                  continue
               elif xr[1] == XR_JCC:
                  self.extract_basic_block_data(func, xr[0], func_insts)
               elif xr[0] in self.thunks:  # must be XR_JUMP
                  continue
               elif xr[0] in self.call_targets:  # must be XR_JUMP to a function
                  # this might/probably needs a callgraph edge
                  continue
               elif xr[0] in self.loader.imports_by_addr:  # must be XR_JUMP
                  continue
               else:  # XR_JUMP, perhaps switch jump ???
                  self.extract_basic_block_data(func, xr[0], func_insts)
            if flows_to != -1:
               addr = flows_to
            else: #no normal flow from here
               break
         else: #no xrefs from here
            break

   #assumes we have all basic blocks identified, we make a second pass here
   #in case we need to associate a bansic block with more than one function
   #this is a result of the binnavi database schema failing to actually
   #set the ex_N_basic_blocks primary key to (id, parent_function) as they 
   #claim to in
   #binnavi/src/main/java/com/google/security/zynamics/binnavi/manual/html/dbformat.htm
   #instead they only use id so we need a unique id when a block is part of more than
   #one function
   def set_basic_block_instructions(self):
      for addr,bb in self.basic_blocks.iteritems():
         seq = 0
         while True:
            inst = self.insts[addr]
            inst.bb = [BlockInfo(b[0], seq, b[1]) for b in bb] #block may belong to more than one function
            seq += 1
            if addr in self.xrefs_from:
               xrefs = self.xrefs_from[addr]
               if self.is_returning_call(xrefs):
                  addr = get_call_targets(xrefs)[0]
               elif len(xrefs) > 1:
                  break
               else: # len(xrefs) == 1
                  addr = xrefs[0][0]
            else: # no xrefs from so at end of block
               break
            if addr in self.basic_blocks: #hit start of different basic block
               break

   #tree is a list of OpNode
   def insert_tree(self, root, tree, depth, pos):
      n = tree[depth]
      n.pos = pos
      depth += 1
      arity = 0
      if (n.op_type % 10) == OPERATOR:
         #operator types are encoded as #4 where # is the arity of the operator
         arity = n.op_type // 10
      if n.op_type == SIZE_PREFIX or n.op_type == DEREFERENCE:
         #also descend on a SIZE_PREFIX
         arity = 1
      
      if n.value not in root:
         #new node at this level
         self.node_id += 1
         n.node_id = self.node_id
         root[n.value] = (n, {})
      else:
         n.node_id = root[n.value][0].node_id      
      self.exprs[self.expr_id].append(root[n.value][0].node_id)
      op_root = root[n.value][1]
      for i in range(arity):
         if i not in op_root:
            op_root[i] = {}
         root = op_root[i]    #different subtrees for different operand position
         #parse the operands for the operator
         depth = self.insert_tree(root, tree, depth, i)
      return depth

   def tree_to_str(self, tree):
      s = ''
      for o in tree:
         s += '(%s)' % str(o.value)
      return s

   def add_expr_tree(self, tree):
      if len(tree) == 0:
         return 0
      s = self.tree_to_str(tree)
      if s in self.expr_strings:
         #we have seen this expression before
         expr_id = self.expr_strings[s]
         idx = 0
         for i in self.exprs[expr_id]:
            tree[idx].node_id = i
            idx += 1
         return expr_id
      # will be making a new expression
      self.expr_id += 1
      self.exprs[self.expr_id] = []
      self.insert_tree(self.nodes, tree, 0, 0)
      self.expr_strings[s] = self.expr_id
      return self.expr_id

   def print_disassembly(self):
      keylist = [a for a in self.visited]    # self.insts.keys()
      keylist.sort()
      last = None
      for a in keylist:
         i = self.insts[a]
         if a in self.names:
            print "%s:" % self.names[a]
         ref = ''
         if i.address not in self.xrefs_to:
            ref = "\t\t**** NOT REFERENCED ****"
         operand = self.get_op_name(i.address, i.op_str)
         print "\t0x%08x:\t%s%s%s" % (i.address, i.mnemonic.ljust(8), operand, ref)
         '''
         if i.address in self.xrefs_from:
            xr = self.xrefs_from[i.address]
            sys.stdout.write('\t')
            for x in xr:
               sys.stdout.write("0x%x(%d), " % (x[0], x[1]))           
            sys.stdout.write('\n')
         '''
         last = i

   def scan_gaps(self, header):
      keylist = [a for a in self.visited]   # self.insts.keys()
      keylist.sort()
      last = None
      count = 0
      for a in keylist:
         i = self.insts[a]
         if last is not None and (last.address + last.size) != a:
            gap_start = last.address + last.size
            gap = self.loader.get_bytes(gap_start, a - gap_start)
            if gap is None:
               print "That's odd, gap is None"
               continue
            idx = 0
            while True:
               loc = gap.find(header, idx)
               if loc != -1 and (loc + gap_start) not in self.visited:
                  self.locs.append(loc + gap_start)
                  #print "Adding gap function 0x%x" % (loc + gap_start)
                  count += 1
                  idx = loc + 1
               else:
                  break
         last = i
      #print "Gap analysis added %d new locations" % count

   #Scan the data sections for possible references back to code
   #such as vtables, switch jumps, and other function pointers
   def scan_data(self):
      pass

   #Scan unanalyzed gaps in the code section for possible references
   #to code such as switch jumps
   def scan_gap_data(self):
      pass

   #subclasses should implement this as it's very platform specific
   def process_operands(self, inst):
      raise Exception("Please implement process_operands")

   #subclasses should implement this
   def process_jump(self, inst):
      raise Exception("Please implement process_jump")

   #subclasses should implement this
   def process_call(self, inst):
      raise Exception("Please implement process_jump")

   #subclasses should implement this
   def get_op_name(self, addr, default_val):
      raise Exception("Please implement get_op_name")

   def add_xref(self, frm, to, xr_type=XR_FLOW):
      raise Exception("Please implement add_xref")

   def nextinst(self, addr):
      #take enough to get at least 1 instruction in majority case
      if addr in self.insts:
         # previously decoded this with capstone
         return self.insts[addr]
      # grab a block of bytes following the current address
      mc = self.loader.get_bytes(addr, 256)
      if mc is None or len(mc) == 0:
         return None
      for i in self.dis.disasm(mc, addr):
         self.insts[i.address] = i
      if addr in self.insts:
         return self.insts[addr]
      return None

   def is_possible_code(self, addr):
      if addr in self.data_locs:
         return False
      for s in self.loader.sections:
         if (s.perms & loader.PROT_EXEC) and s.contains(addr):
            return True
      return False

   def generate_disassembly(self):
      while len(self.locs) > 0:
         addr = self.locs.pop(0)
         if not self.is_possible_code(addr):
            continue
         dead_end = False
         while True:
            i = self.nextinst(addr)
            if i is None:
               # but we should have gotten an instruction so this is odd
               # remove all xrefs to this address
               if addr in self.xrefs_to:
                  srcs = self.xrefs_to[addr]
                  for s in srcs:
                     if s[0] in self.xrefs_from:
                        dests = self.xrefs_from[s[0]]
                        for tgt in dests:
                           if tgt[0] == addr:
                              dests.remove(tgt)
                              break
                  self.xrefs_to.pop(addr, None)
               break
            if i.address in self.visited:
               #already been here, won't learn anything new
               break
            self.visited.add(i.address)
            self.insts[i.address] = i
            self.process_operands(i)
            
            dead_end = False
            if i.group(capstone.CS_GRP_JUMP):
               dead_end = self.process_jump(i)
            elif i.group(capstone.CS_GRP_CALL):
               dead_end = self.process_call(i)
            elif i.group(capstone.CS_GRP_RET):
               dead_end = True
            elif i.group(capstone.CS_GRP_IRET):
               dead_end = True
            if not dead_end:
               next_addr = i.address + i.size
               self.add_xref(i.address, next_addr)
            else:
               #dead end return to instruction list
               break

   def generate_data(self):
      self.generate_disassembly()
   
      print "After first pass, have %d insts" % len(self.visited)
   
      main = self.loader.find_main(self.insts, self.xrefs_to, self.xrefs_from)
      if main is not None and main not in self.visited:
         self.locs.append(main)
         self.call_targets.add(main)
         self.add_basic_block_start(main)
         if "main" not in self.names:
            self.names[main] = "main"
         elif "_main" not in self.names:
            self.names[main] = "_main"
         else:
            self.names[main] = "sub_%x" % main
      self.generate_disassembly()   

      print "After 'find_main' pass, have %d insts" % len(self.visited)
   
      #pick up pointers in the rdata section
#      self.scan_data()
#      self.generate_disassembly()
   
#      for sig in self.func_sigs:
         #try to find more code by looking for standard prologue
#         self.scan_gaps(sig)
#         self.generate_disassembly()
   
      #pick up pointers in the text section
#      self.scan_gap_data()
#      self.generate_disassembly()

      for f in self.call_targets:
         self.extract_basic_block_data(f, f, set())
      self.set_basic_block_instructions()
      self.build_cfg()
      self.build_callgraph()
      for addr,bb in self.basic_blocks.iteritems():
         if len(bb) == 0:
            print "no parent found for basic block at 0x%x" % addr
      for addr in self.visited:
         i = self.insts[addr]
         if not hasattr(i, "bb"):
            print "Instruction 0x%x has no bb" % addr
