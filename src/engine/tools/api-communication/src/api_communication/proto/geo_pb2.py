# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: geo.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import builder as _builder
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import api_communication.proto.engine_pb2 as _engine_pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\tgeo.proto\x12\x18\x63om.cyb3rhq.api.engine.geo\x1a\x0c\x65ngine.proto\"3\n\x07\x44\x62\x45ntry\x12\x0c\n\x04name\x18\x01 \x01(\t\x12\x0c\n\x04path\x18\x02 \x01(\t\x12\x0c\n\x04type\x18\x03 \x01(\t\",\n\x0e\x44\x62Post_Request\x12\x0c\n\x04path\x18\x01 \x01(\t\x12\x0c\n\x04type\x18\x02 \x01(\t\" \n\x10\x44\x62\x44\x65lete_Request\x12\x0c\n\x04path\x18\x01 \x01(\t\"\x10\n\x0e\x44\x62List_Request\"\x97\x01\n\x0f\x44\x62List_Response\x12\x32\n\x06status\x18\x01 \x01(\x0e\x32\".com.cyb3rhq.api.engine.ReturnStatus\x12\x12\n\x05\x65rror\x18\x02 \x01(\tH\x00\x88\x01\x01\x12\x32\n\x07\x65ntries\x18\x03 \x03(\x0b\x32!.com.cyb3rhq.api.engine.geo.DbEntryB\x08\n\x06_error\"T\n\x16\x44\x62RemoteUpsert_Request\x12\x0c\n\x04path\x18\x01 \x01(\t\x12\x0c\n\x04type\x18\x02 \x01(\t\x12\r\n\x05\x64\x62Url\x18\x03 \x01(\t\x12\x0f\n\x07hashUrl\x18\x04 \x01(\tb\x06proto3')

_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, globals())
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'geo_pb2', globals())
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _DBENTRY._serialized_start=53
  _DBENTRY._serialized_end=104
  _DBPOST_REQUEST._serialized_start=106
  _DBPOST_REQUEST._serialized_end=150
  _DBDELETE_REQUEST._serialized_start=152
  _DBDELETE_REQUEST._serialized_end=184
  _DBLIST_REQUEST._serialized_start=186
  _DBLIST_REQUEST._serialized_end=202
  _DBLIST_RESPONSE._serialized_start=205
  _DBLIST_RESPONSE._serialized_end=356
  _DBREMOTEUPSERT_REQUEST._serialized_start=358
  _DBREMOTEUPSERT_REQUEST._serialized_end=442
# @@protoc_insertion_point(module_scope)
