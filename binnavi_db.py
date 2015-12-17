#!/usr/bin/env python

'''
The database interface for a stand-alone binnavi compatible disassembler
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
import traceback
import struct
import hashlib
import psycopg2
import capstone
import bn_disasm

FUNCTION_TYPES = {'NORMAL':0, 'LIBRARY':1, 'IMPORTED':2, 'THUNK':3, 'INAVALID':4,}

class binnavi_db(object):

   def __init__(self, db, user, passwd, host='localhost'):
#      try:
         self.conn = psycopg2.connect("dbname='%s' user='%s' host='%s' password='%s'" % (db, user, host, passwd))
         self.create_empty_tables()
#      except Exception, e:
#         raise Exception("db connect fail: %s:%s" % (type(e), e.message))

   def export(self, module_data):
      return self.add_module(module_data)

   def add_functions(self, curs, id, module_data):
      for addr in module_data.call_targets:
         name = module_data.names[addr]
         named = not name.startswith('sub_')
         demangled = None   #demangle(name)
         ftype = FUNCTION_TYPES['NORMAL']  #NORMAL
         if addr in module_data.loader.imports_by_addr:
            ftype = FUNCTION_TYPES['IMPORT']
         elif addr in module_data.thunks:
            ftype = FUNCTION_TYPES['THUNK']
         #not working yet, but if a function has a stack frame, it will be named: "__SF%x" % addr
         stkframe = None
         if ("__SF%x" % addr) in module_data.types:
            stkframe = module_data.types["__SF%x" % addr].id
         curs.execute("insert into ex_%d_functions values (%%s, %%s, %%s, %%s, %%s, %%s, %%s, %%s);" % id,
                     (addr, name, demangled, named, ftype, module_data.loader.name, stkframe, None))

   def add_instructions(self, curs, id, module_data):
      for addr in module_data.visited:
         insn = module_data.insts[addr]
         curs.execute("insert into ex_%d_instructions values (%%s, %%s, %%s);" % id, (addr, insn.mnemonic, insn.bytes))

   #called from inside a with block already, so take a cursor from the caller
   #computes the basic block members from the give start address
   def add_basic_block_instructions(self, curs, id, module_data):
      for addr in module_data.visited:
         i = module_data.insts[addr]
         if hasattr(i, "bb"):
            for b in i.bb:
               curs.execute("insert into ex_%d_basic_block_instructions values (%%s, %%s, %%s);" % id, (b.bid, addr, b.seq))

   # also, build the cgf while we're at it
   def add_basic_blocks(self, curs, id, module_data):
      for addr,bb in module_data.basic_blocks.iteritems():
         for block in bb:
            curs.execute("insert into ex_%d_basic_blocks values (%%s, %%s, %%s);" % id, (block[0], block[1], addr))

   def drop_table(self, curs, table):
      curs.execute("drop table if exists %s cascade;" % table)

   def delete_raw_module(self, curs, id):
      self.drop_table(curs, "ex_%d_address_comments" % id)
      self.drop_table(curs, "ex_%d_address_references" % id)
      self.drop_table(curs, "ex_%d_expression_substitutions" % id)
      self.drop_table(curs, "ex_%d_operands" % id)
      self.drop_table(curs, "ex_%d_expression_tree_nodes" % id)
      self.drop_table(curs, "ex_%d_expression_trees" % id)
      self.drop_table(curs, "ex_%d_expression_nodes" % id)
      self.drop_table(curs, "ex_%d_control_flow_graphs" % id)
      self.drop_table(curs, "ex_%d_callgraph" % id)
      self.drop_table(curs, "ex_%d_basic_block_instructions" % id)
      self.drop_table(curs, "ex_%d_instructions" % id)
      self.drop_table(curs, "ex_%d_basic_blocks" % id)
      self.drop_table(curs, "ex_%d_functions" % id)
      self.drop_table(curs, "ex_%d_type_renderers" % id)
      self.drop_table(curs, "ex_%d_base_types" % id)
      self.drop_table(curs, "ex_%d_expression_type_instances" % id)
      self.drop_table(curs, "ex_%d_expression_types" % id)
      self.drop_table(curs, "ex_%d_types" % id)
      self.drop_table(curs, "ex_%d_type_instances" % id)
      self.drop_table(curs, "ex_%d_sections" % id)
      self.drop_table(curs, "ex_%d_type_substitution_paths" % id)

   def create_raw_module(self, curs, id):
      curs.execute('create table ex_%d_functions ("address" bigint not null, "name" text not null,"demangled_name" text null default null,"has_real_name" boolean not null,"type" int not null default 0 check( "type" in ( 0, 1, 2, 3, 4 )),"module_name" text null default null,"stack_frame" int null default null,"prototype" int null default null);' % id)
      curs.execute('create table ex_%d_basic_blocks ("id" int not null,"parent_function" bigint not null,"address" bigint not null);' % id)
      curs.execute('create table ex_%d_instructions ("address" bigint not null,"mnemonic" varchar( 32 ) not null,"data" bytea not null);' % id)
      curs.execute('create table ex_%d_basic_block_instructions ("basic_block_id" int not null,"instruction" bigint not null,"sequence" int not null);' % id)
      curs.execute('create table ex_%d_callgraph ("id" serial,"source" bigint not null,"source_basic_block_id" int not null,"source_address" bigint not null,"destination" bigint not null);' % id)
      curs.execute('create table ex_%d_control_flow_graphs ("id" serial,"parent_function" bigint not null,"source" int not null,"destination" int not null,"type" int not null default 0 check( "type" in ( 0, 1, 2, 3 )));' % id)
      curs.execute('create table ex_%d_expression_trees ("id" serial);' % id)
      curs.execute('create table ex_%d_expression_nodes ("id" serial,"type" int not null default 0 check( "type" >= 0 and "type" <= 7 ),"symbol" varchar( 256 ),"immediate" bigint,"position" int,"parent_id" int check( "id" > "parent_id" ));' % id)
      curs.execute('create table ex_%d_expression_tree_nodes ("expression_tree_id" int not null,"expression_node_id" int not null);' % id)
      curs.execute('create table ex_%d_operands ("address" bigint not null,"expression_tree_id" int not null,"position" int not null);' % id)
      curs.execute('create table ex_%d_expression_substitutions ("id" serial,"address" bigint not null,"position" int not null,"expression_node_id" int not null,"replacement" text not null);' % id)
      curs.execute('create table ex_%d_address_references ("address" bigint not null,"position" int null,"expression_node_id" int null,"destination" bigint not null,"type" int not null default 0 check( "type" >= 0 and "type" <= 8 ));' % id)
      curs.execute('create table ex_%d_address_comments ("address" bigint not null,"comment" text not null);' % id)
      curs.execute('drop type if exists ex_%d_type_category;' % id)
      curs.execute("create type ex_%d_type_category as enum ('atomic', 'pointer', 'array','struct', 'union', 'function_pointer');" % id)
      curs.execute('create table ex_%d_base_types ("id" integer not null,"name" text not null,"size" integer not null,"pointer" integer,"signed" bool,"category" ex_%d_type_category not null);' % (id, id))
      curs.execute('create table ex_%d_types ("id" serial not null,"name" text not null,"base_type" integer not null,"parent_id" integer,"offset" integer,"argument" integer,"number_of_elements" integer);' % id)
      curs.execute('drop type if exists ex_%d_type_renderers_renderer_type;' % id)
      curs.execute("create type ex_%d_type_renderers_renderer_type as enum ('integer','floating point', 'boolean', 'ascii', 'utf8', 'utf16');" % id)
      curs.execute('create table ex_%d_type_renderers ("type_id" int not null,"renderer" ex_%d_type_renderers_renderer_type not null);' % (id, id))
      curs.execute('drop type if exists ex_%d_section_permission_type;' % id)
      curs.execute("create type ex_%d_section_permission_type as enum ('READ', 'WRITE','EXECUTE', 'READ_WRITE', 'READ_EXECUTE', 'WRITE_EXECUTE','READ_WRITE_EXECUTE');" % id)
      curs.execute('create table ex_%d_sections ("id" serial not null,"name" text not null,"start_address" bigint not null,"end_address" bigint not null,"permission" ex_%d_section_permission_type not null,"data" bytea not null);' % (id, id))
      curs.execute('create table ex_%d_expression_types ("address" bigint not null,"position" integer not null,"expression_id" integer not null,"type" integer not null,"path" integer[] not null,"offset" integer);' % id)
      curs.execute('create table ex_%d_expression_type_instances ("address" bigint not null,"position" integer not null,"expression_node_id" integer not null,"type_instance_id" integer not null);' % id)
      curs.execute('create table ex_%d_type_instances ("id" integer not null,"name" text not null,"section_offset" bigint not null,"type_id" integer not null,"section_id" integer not null);' % id)
      curs.execute('create table ex_%d_type_substitution_paths ("id" integer not null,"child_id" integer,"type_id" integer not null);' % id)

   def vaccuum_raw_tables(self, id):
      try:
         with self.conn as conn:
            old_iso = conn.isolation_level
            conn.set_isolation_level(0)
            with conn.cursor() as curs:
               curs.execute('vacuum analyze "ex_%d_operands";' % id)
               curs.execute('vacuum analyze "ex_%d_functions";' % id)
               curs.execute('vacuum analyze "ex_%d_basic_blocks";' % id)
               curs.execute('vacuum analyze "ex_%d_instructions";' % id)
               curs.execute('vacuum analyze "ex_%d_basic_block_instructions";' % id)
               curs.execute('vacuum analyze "ex_%d_callgraph";' % id)
               curs.execute('vacuum analyze "ex_%d_control_flow_graphs";' % id)
               curs.execute('vacuum analyze "ex_%d_expression_trees";' % id)
               curs.execute('vacuum analyze "ex_%d_expression_nodes";' % id)
               curs.execute('vacuum analyze "ex_%d_expression_tree_nodes";' % id)
               curs.execute('vacuum analyze "ex_%d_expression_substitutions";' % id)
               curs.execute('vacuum analyze "ex_%d_address_references";' % id)
               curs.execute('vacuum analyze "ex_%d_address_comments";' % id)
               curs.execute('vacuum analyze "ex_%d_type_renderers";' % id)
               curs.execute('vacuum analyze "ex_%d_base_types";' % id)
               curs.execute('vacuum analyze "ex_%d_types";' % id)
               curs.execute('vacuum analyze "ex_%d_expression_types";' % id)
               curs.execute('vacuum analyze "ex_%d_sections";' % id)
            conn.set_isolation_level(old_iso)
      except psycopg2.Error, p:
         print "vaccuum_raw_tables: %s" % p.message
         raise p

   def create_raw_indicies(self, curs, id):
      curs.execute('create unique index ex_%d_functions_address_idx on ex_%d_functions( "address" );' % (id, id))
      curs.execute('create unique index ex_%d_basic_blocks_id_idx on ex_%d_basic_blocks( "id" );' % (id, id))
      curs.execute('create index ex_%d_basic_blocks_address_idx on ex_%d_basic_blocks( "address" );' % (id, id))
      curs.execute('create unique index ex_%d_instructions_address_idx on ex_%d_instructions( "address" );' % (id, id))
      curs.execute('create unique index ex_%d_expression_trees_id_idx on ex_%d_expression_trees( "id" );' % (id, id))
      curs.execute('create unique index ex_%d_expression_nodes_id_idx on ex_%d_expression_nodes( "id" );' % (id, id))

   def delete_cleanup(self, curs, id):
      curs.execute("delete from ex_%d_instructions as instructions using ex_%d_basic_block_instructions as basic_block_instructions where basic_block_instructions.instruction = instructions.address and basic_block_id is null;" % (id, id))
      curs.execute("delete from ex_%d_basic_block_instructions where basic_block_id is null;" % id)
      curs.execute("delete from ex_%d_address_references where address in ( select address from ex_%d_address_references except select address from ex_%d_instructions);" % (id, id, id))
      curs.execute("delete from ex_%d_address_comments where address in ( select address from ex_%d_address_comments except select address from ex_%d_instructions);" % (id, id, id))
      curs.execute("delete from ex_%d_expression_substitutions where address in ( select address from ex_%d_expression_substitutions except select address from ex_%d_instructions);" % (id, id, id))
      curs.execute("delete from ex_%d_operands where address in ( select address from ex_%d_operands except select address from ex_%d_instructions);" % (id, id, id))
      curs.execute("delete from ex_%d_expression_type_instances where address in ( select address from ex_%d_expression_type_instances except select address from ex_%d_operands);" % (id, id, id))

   def create_raw_keys(self, curs, id):
      curs.execute('alter table ex_%d_functions add primary key( "address" );' % id)
      curs.execute('alter table ex_%d_basic_blocks add primary key( "id" );' % id)
      curs.execute('alter table ex_%d_basic_blocks add constraint ex_%d_basic_blocks_parent_function_fkey foreign key ( "parent_function" ) references ex_%d_functions( "address" ) on delete cascade on update cascade;' % (id, id, id))
      curs.execute('alter table ex_%d_instructions add primary key( "address" );' % id)
      curs.execute('alter table ex_%d_basic_block_instructions add constraint ex_%d_basic_block_instructions_bb_fkey foreign key ( "basic_block_id" ) references ex_%d_basic_blocks( "id" ) on delete cascade on update cascade;' % (id, id, id))
      curs.execute('alter table ex_%d_basic_block_instructions add constraint ex_%d_basic_block_instructions_ins_fkey foreign key ( "instruction" ) references ex_%d_instructions( "address" ) on delete cascade on update cascade;' % (id, id, id))
      curs.execute('alter table ex_%d_callgraph add primary key( "id" );' % id)
      curs.execute('alter table ex_%d_callgraph add constraint ex_%d_callgraph_source_fkey foreign key ( "source" ) references ex_%d_functions( "address" ) on delete cascade on update cascade;' % (id, id, id))
      curs.execute('alter table ex_%d_callgraph add constraint ex_%d_callgraph_destination_fkey foreign key ( "destination" ) references ex_%d_functions( "address" ) on delete cascade on update cascade;' % (id, id, id))
      curs.execute('alter table ex_%d_callgraph add constraint ex_%d_callgraph_source_basic_block_id_fkey foreign key ( "source_basic_block_id" ) references ex_%d_basic_blocks( "id" ) on delete cascade on update cascade;' % (id, id, id))
      curs.execute('alter table ex_%d_callgraph add constraint ex_%d_callgraph_source_address_fkey foreign key ( "source_address" ) references ex_%d_instructions( "address" ) on delete cascade on update cascade;' % (id, id, id))
      curs.execute('alter table ex_%d_control_flow_graphs add primary key( "id" );' % id)
      curs.execute('alter table ex_%d_control_flow_graphs add constraint ex_%d_control_flow_graphs_parent_function_fkey foreign key ( "parent_function" ) references ex_%d_functions( "address" ) on delete cascade on update cascade;' % (id, id, id))
      curs.execute('alter table ex_%d_control_flow_graphs add constraint ex_%d_control_flow_graphs_source_fkey foreign key ( "source" ) references ex_%d_basic_blocks( "id" ) on delete cascade on update cascade;' % (id, id, id))
      curs.execute('alter table ex_%d_control_flow_graphs add constraint ex_%d_control_flow_graphs_destination_fkey foreign key ( "destination" ) references ex_%d_basic_blocks( "id" ) on delete cascade on update cascade;' % (id, id, id))
      curs.execute('alter table ex_%d_expression_trees add primary key( "id" );' % id)
      curs.execute('alter table ex_%d_expression_nodes add primary key( "id" );' % id)
      curs.execute('alter table ex_%d_expression_nodes add constraint ex_%d_expression_nodes_parent_id_fkey foreign key ( "parent_id" ) references ex_%d_expression_nodes( "id" ) on delete cascade on update cascade;' % (id, id, id))
      curs.execute('alter table ex_%d_expression_tree_nodes add constraint ex_%d_expression_tree_nodes_expression_tree_id_fkey foreign key ( "expression_tree_id" ) references ex_%d_expression_trees( "id" ) on delete cascade on update cascade;' % (id, id, id))
      curs.execute('alter table ex_%d_expression_tree_nodes add constraint ex_%d_expression_tree_nodes_expression_node_id_fkey foreign key ( "expression_node_id" ) references ex_%d_expression_nodes( "id" ) on delete cascade on update cascade;' % (id, id, id))
      curs.execute('alter table ex_%d_operands add primary key ( "address", "position" );' % id)
      curs.execute('alter table ex_%d_operands add constraint ex_%d_operands_expression_tree_id_fkey foreign key ( "expression_tree_id" ) references ex_%d_expression_trees( "id" ) on delete cascade on update cascade;' % (id, id, id))
      curs.execute('alter table ex_%d_operands add constraint ex_%d_operands_address_fkey foreign key ( "address" ) references ex_%d_instructions( "address" ) on delete cascade on update cascade;' % (id, id, id))
      curs.execute('alter table ex_%d_expression_substitutions add constraint ex_%d_expression_substitutions_address_position_fkey foreign key ( "address", "position" ) references ex_%d_operands( "address", "position" ) on delete cascade on update cascade;' % (id, id, id))
      curs.execute('alter table ex_%d_expression_substitutions add constraint ex_%d_expression_substitutions_expression_node_id_fkey foreign key ( "expression_node_id" ) references ex_%d_expression_nodes( "id" ) on delete cascade on update cascade;' % (id, id, id))
      curs.execute('alter table ex_%d_address_references add constraint ex_%d_address_references_address_position foreign key ( "address", "position" ) references ex_%d_operands( "address", "position" ) on delete cascade on update cascade;' % (id, id, id))
      curs.execute('alter table ex_%d_address_references add constraint ex_%d_address_references_expression_node_id_fkey foreign key ( "expression_node_id" ) references ex_%d_expression_nodes( "id" ) on delete cascade on update cascade;' % (id, id, id))
      curs.execute('alter table ex_%d_base_types add primary key ( "id" );' % id)
      curs.execute('alter table ex_%d_base_types add constraint ex_%d_base_types_pointer_fkey foreign key ( "pointer" ) references ex_%d_base_types( "id" ) on delete cascade on update cascade deferrable initially deferred;' % (id, id, id))
      curs.execute('alter table ex_%d_types add primary key ( "id");' % id)
      curs.execute('alter table ex_%d_types add constraint ex_%d_types_parent_id_fkey foreign key ( "parent_id" ) references ex_%d_base_types ( "id" ) on delete cascade on update cascade deferrable initially deferred;' % (id, id, id))
      curs.execute('alter table ex_%d_types add constraint ex_%d_types_base_type_fkey foreign key ( "base_type" ) references ex_%d_base_types ( "id" ) on delete cascade on update cascade;' % (id, id, id))
      curs.execute('alter table ex_%d_expression_types add primary key ( "address", "position", "expression_id" );' % id)
      curs.execute('alter table ex_%d_expression_types add constraint ex_%d_expression_type_type_fkey foreign key ( "type" ) references ex_%d_base_types ( "id" ) on update no action on delete cascade deferrable initially deferred;' % (id, id, id))
      curs.execute('alter table ex_%d_sections add primary key ( "id" );' % id)
      curs.execute('alter table ex_%d_type_instances add primary key ( "id" );' % id)
      curs.execute('alter table ex_%d_type_instances add constraint ex_%d_type_instances_type_id_fkey foreign key ( "type_id" ) references ex_%d_base_types ( "id" ) match simple on update cascade on delete cascade;' % (id, id, id))
      curs.execute('alter table ex_%d_type_instances add constraint ex_%d_type_instances_section_id_fkey foreign key ( "section_id" ) references ex_%d_sections ( "id" ) match simple on update cascade on delete cascade;' % (id, id, id))
      curs.execute('alter table ex_%d_expression_type_instances add primary key ( "address", "position", "expression_node_id" );' % id)
      curs.execute('alter table ex_%d_expression_type_instances add constraint ex_%d_expression_type_instances_type_instance_id_fkey foreign key ( "type_instance_id" ) references ex_%d_type_instances ( "id" ) match simple on update cascade on delete cascade;' % (id, id, id))
      curs.execute('alter table ex_%d_expression_type_instances add constraint ex_%d_expression_type_instances_address_position_fkey foreign key ( "address", "position" ) references ex_%d_operands ( "address", "position" ) match simple on update cascade on delete cascade;' % (id, id, id))
      curs.execute('alter table ex_%d_expression_type_instances add constraint ex_%d_expression_type_instances_expression_node_id_fkey foreign key ( "expression_node_id" ) references ex_%d_expression_nodes ( "id" ) match simple on update cascade on delete cascade;' % (id, id, id))

   def has_table(self, curs, table):
      result = False
      try:
         curs.execute("SELECT relname FROM pg_class WHERE relname = %s;", (table, ))
         result = curs.rowcount == 1
      except psycopg2.Error, p:
         print "has_table: %s" % p.message
         raise p
      return result

   def need_pg_init(self, curs):
      try:
         curs.execute('''SELECT count(*) FROM pg_class WHERE relname in ('bn_projects','bn_modules',
            'bn_address_spaces','bn_space_modules','bn_functions','bn_function_views','bn_instructions',
            'bn_operands','bn_expression_tree','bn_expression_tree_ids','bn_expression_tree_mapping',
            'bn_code_nodes','bn_codenode_instructions','bn_edges','bn_edge_paths','bn_function_nodes',
            'bn_group_nodes','bn_nodes','bn_project_settings','bn_module_settings','bn_traces','bn_trace_events',
            'bn_trace_event_values','bn_views','bn_module_views','bn_project_views','bn_view_settings',
            'bn_global_edge_comments','bn_global_node_comments','bn_project_debuggers','bn_debuggers',
            'bn_tags','bn_tagged_views','bn_tagged_nodes','bn_expression_substitutions','bn_comments',
            'bn_comments_audit','bn_types','bn_base_types','bn_users','bn_expression_types')''')
         res = curs.fetchone()[0]
         return res != 41
      except psycopg2.Error, p:
         print "need_pg_init: %s" % p.message
         raise p
      return True

   def create_modules_table(self):
      try:
         with self.conn as conn:
            with conn.cursor() as curs:
               query = ("CREATE TABLE modules ("
                        " id serial, "
                        " name text NOT NULL, "
                        " architecture varchar( 32 ) NOT NULL, "
                        " base_address bigint NOT NULL, "
                        " exporter varchar( 256 ) NOT NULL, "
                        " version int NOT NULL, "
                        " md5 char( 32 ) NOT NULL, "
                        " sha1 char( 40 ) NOT NULL, "
                        " comment TEXT, "
                        " import_time timestamp NOT NULL DEFAULT current_timestamp, "
                        " PRIMARY KEY (id));")
               curs.execute(query)
      except psycopg2.Error, p:
         print "create_modules_table: %s" % p.message
         raise p

   def delete_module(self, id):
      try:
         with self.conn as conn:
            with conn.cursor() as curs:
               curs.execute("delete from modules where id = %s;", (id, ))
               self.delete_raw_module(curs, id)
      except psycopg2.Error, p:
         print "delete_module: %s" % p.message
         raise p

   def insert_module(self, id, module_data):
      try:
         with self.conn as conn:
            with conn.cursor() as curs:
               curs.execute("insert into modules values(%s, %s, %s, %s, %s, %s, %s, %s, %s, now());",
                            (id, module_data.loader.name, module_data.loader.arch_name, module_data.loader.image_base, 'infiltrated', 0,
                             module_data.loader.md5, module_data.loader.sha1, module_data.comment))
      except psycopg2.Error, p:
         print "insert_module: %s" % p.message
         raise p

   def add_sections(self, curs, id, module_data):
      for s in module_data.loader.sections:
         raw = s.get_raw_bytes(module_data.loader)
         if raw is not None:
            curs.execute(("insert into ex_%d_sections"
                         "(name, start_address, end_address, permission, data)"
                         " values (%%s, %%s, %%s, %%s, %%s);" % id),
                         (s.name, s.start, s.end, bn_disasm.PERMISSIONS[s.perms], bytearray(raw)))

   def add_operands(self, curs, id, module_data):
      for addr in module_data.visited:
         op_exprs = module_data.operands[addr]
         opnum = 0
         '''
         if not hasattr(insn, "op_exprs"):
            print "Missing op_exprs for 0x%x" % insn.address
            continue
         if insn.op_exprs is None:
            print "op_exprs == None for 0x%x" % insn.address
            continue
         '''
         for expr in op_exprs:
            curs.execute(("insert into ex_%d_operands"
                         "(address, expression_tree_id, position)"
                         " values (%%s, %%s, %%s);" % id),
                         (addr, expr, opnum))
            opnum += 1

   def add_nodes(self, curs, id, module_data, nodes, parent):
      for key,value in nodes.iteritems():
         node = value[0]
         val = None
         if node.op_type == bn_disasm.IMMEDIATE_INT:
            val = node.value
            if node.value in module_data.names:
               key = module_data.names[node.value]
            else:
               key = None
         curs.execute(("insert into ex_%d_expression_nodes"
                      "(id, type, symbol, immediate, position, parent_id)"
                      " values (%%s, %%s, %%s, %%s, %%s, %%s);" % id),
                      (node.node_id, node.op_type % 10, key, val, node.pos, parent))
         for pos,op in value[1].iteritems():
            self.add_nodes(curs, id, module_data, op, node.node_id)

   def add_trees(self, curs, id, module_data):
      for expr in module_data.exprs.keys():
         curs.execute(("insert into ex_%d_expression_trees"
                      "(id)"
                      " values (%%s);" % id),
                      (expr, ))

   def add_tree_nodes(self, curs, id, module_data):
      for expr,nodes in module_data.exprs.iteritems():
         for n in nodes:
            curs.execute(("insert into ex_%d_expression_tree_nodes"
                         "(expression_tree_id, expression_node_id)"
                         " values (%%s, %%s);" % id),
                         (expr, n))

   def add_types(self, curs, id, module_data):
      for name,btype in module_data.types.iteritems():
         curs.execute(("insert into ex_%d_base_types"
                      "(id, name, size, pointer, signed, category)"
                      " values (%%s, %%s, %%s, %%s, %%s, %%s);" % id),
                      (btype.id, btype.name, btype.size, btype.pointer, btype.signed, bn_disasm.TYPE_CATEGORIES[btype.category]))

   def add_arefs(self, curs, id, module_data):
      for aref in module_data.arefs:
         curs.execute(("insert into ex_%d_address_references"
                      "(address, position, expression_node_id, destination, type)"
                      " values (%%s, %%s, %%s, %%s, %%s);" % id),
                      (aref.addr, aref.pos, aref.node_id, aref.dest, aref.rtype))

   def add_module(self, module_data):
      try:
         id = 0
         with self.conn as conn:
            with conn.cursor() as curs:
               curs.execute("select coalesce(max(id), 0) + 1 from modules;")
               id = curs.fetchone()[0]
         self.insert_module(id, module_data)

         with self.conn as conn:
            with conn.cursor() as curs:
               # ordering as binnavi's Ida plugin seems to
               #begin is here
               self.delete_raw_module(curs, id)
               self.create_raw_module(curs, id)
               #binnavi then adds sections here
               sys.stderr.write("add_sections\n")
               self.add_sections(curs, id, module_data)

               #next binnavi inserts into base_types table
               #    some basic types, then enumerates IDA's structs window, then adds types for all functions ('struct' ???)
               #   (1,'BYTE',8,181,true,'atomic'),
               #   (2,'WORD',16,181,true,'atomic'),
               #   (3,'DWORD',32,181,true,'atomic'),
               #   (4,'QWORD',64,null,true,'atomic'),
               #   (5,'void',32,181,false,'atomic'),
               #   (6,'void *',32,5,false,'atomic')
               sys.stderr.write("add_types\n")
               self.add_types(curs, id, module_data)
               #next binnavi inserts into types table
               #next into expression_types
               #          type_instances
               #          expression_type_instances
               #          address_comments

               sys.stderr.write("add_operands\n")
               self.add_operands(curs, id, module_data)
               sys.stderr.write("add_instructions\n")
               self.add_instructions(curs, id, module_data)
               #functions must have non-null stack_frame
               sys.stderr.write("add_functions\n")
               self.add_functions(curs, id, module_data)
               sys.stderr.write("add_basic_blocks\n")
               self.add_basic_blocks(curs, id, module_data)
               #          basic_block_instructions
               self.add_basic_block_instructions(curs, id, module_data)

               cfg_query = ("insert into ex_%d_control_flow_graphs"
                            "(parent_function, source, destination, type)"
                            " values (%%s, %%s, %%s, %%s);") % id
               for edge in module_data.cfg:
                  curs.execute(cfg_query, (edge.parent_func, edge.src_bb, edge.dest_bb, edge.edge_type))

               cg_query = ("insert into ex_%d_callgraph"
                           "(source, source_basic_block_id, source_address, destination)"
                           " values (%%s, %%s, %%s, %%s);") % id
               for edge in module_data.callgraph:
                  curs.execute(cg_query, (edge.src_func, edge.src_bb, edge.src_addr, edge.dest))

               sys.stderr.write("add_nodes\n")
               self.add_nodes(curs, id, module_data, module_data.nodes, None)
               #          expression_trees
               sys.stderr.write("add_trees\n")
               self.add_trees(curs, id, module_data)
               #          expression_tree_nodes
               sys.stderr.write("add_tree_nodes\n")
               self.add_tree_nodes(curs, id, module_data)

               #create indicies
               self.create_raw_indicies(curs, id)

               #          expression_substitutions
               #          address_references
               self.add_arefs(curs, id, module_data)

               #next a number of delete queries are executed
               self.delete_cleanup(curs, id)
               #now add indicies/foreign keys on all tables that need them
               self.create_raw_keys(curs, id)
               #commit is here

         self.vaccuum_raw_tables(id)

         return id
      except psycopg2.Error, p:
         traceback.print_exc()
         print "add_module: %s" % p.message
         raise p
      return -1

   def create_empty_tables(self):
      try:
         with self.conn as conn:
            with conn.cursor() as curs:
               if not self.has_table(curs, "modules"):
                  query = ("CREATE TABLE modules ("
                           " id serial, "
                           " name text NOT NULL, "
                           " architecture varchar( 32 ) NOT NULL, "
                           " base_address bigint NOT NULL, "
                           " exporter varchar( 256 ) NOT NULL, "
                           " version int NOT NULL, "
                           " md5 char( 32 ) NOT NULL, "
                           " sha1 char( 40 ) NOT NULL, "
                           " comment TEXT, "
                           " import_time timestamp NOT NULL DEFAULT current_timestamp, "
                           " PRIMARY KEY (id));")
                  curs.execute(query)

               if self.need_pg_init(curs):
                  with open('postgresql_tables.sql') as sql:
                     build_tables = sql.read()
                     curs.execute(build_tables)
                  curs.execute("INSERT INTO bn_users VALUES (DEFAULT, 'identity', null, null);")
      except psycopg2.Error, p:
         print "create_empty_tables: %s" % p.message
