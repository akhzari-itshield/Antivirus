"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import runtime_version as _runtime_version
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
_runtime_version.ValidateProtobufRuntimeVersion(
    _runtime_version.Domain.PUBLIC,
    7,
    35,
    1,
    '',
    'protocol.proto'
)

_sym_db = _symbol_database.Default()


from google.protobuf import struct_pb2 as google_dot_protobuf_dot_struct__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x0eprotocol.proto\x12\x08itshield\x1a\x1cgoogle/protobuf/struct.proto\"E\n\x07Request\x12\x11\n\toperation\x18\x01 \x01(\t\x12\'\n\x06params\x18\x02 \x01(\x0b\x32\x17.google.protobuf.Struct\"m\n\x08Response\x12\x0f\n\x07success\x18\x01 \x01(\x08\x12\x12\n\nerror_code\x18\x02 \x01(\t\x12\x15\n\rerror_message\x18\x03 \x01(\t\x12%\n\x04\x64\x61ta\x18\x04 \x01(\x0b\x32\x17.google.protobuf.Structb\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'protocol_pb2', _globals)
if not _descriptor._USE_C_DESCRIPTORS:
  DESCRIPTOR._loaded_options = None
  _globals['_REQUEST']._serialized_start=58
  _globals['_REQUEST']._serialized_end=127
  _globals['_RESPONSE']._serialized_start=129
  _globals['_RESPONSE']._serialized_end=238
