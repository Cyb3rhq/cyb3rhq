// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: graph.proto

#include "graph.pb.h"

#include <algorithm>

#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/extension_set.h>
#include <google/protobuf/wire_format_lite.h>
#include <google/protobuf/descriptor.h>
#include <google/protobuf/generated_message_reflection.h>
#include <google/protobuf/reflection_ops.h>
#include <google/protobuf/wire_format.h>
// @@protoc_insertion_point(includes)
#include <google/protobuf/port_def.inc>

PROTOBUF_PRAGMA_INIT_SEG

namespace _pb = ::PROTOBUF_NAMESPACE_ID;
namespace _pbi = _pb::internal;

namespace com {
namespace cyb3rhq {
namespace api {
namespace engine {
namespace graph {
PROTOBUF_CONSTEXPR GraphGet_Request::GraphGet_Request(
    ::_pbi::ConstantInitialized): _impl_{
    /*decltype(_impl_._has_bits_)*/{}
  , /*decltype(_impl_._cached_size_)*/{}
  , /*decltype(_impl_.policy_)*/{&::_pbi::fixed_address_empty_string, ::_pbi::ConstantInitialized{}}
  , /*decltype(_impl_.type_)*/{&::_pbi::fixed_address_empty_string, ::_pbi::ConstantInitialized{}}} {}
struct GraphGet_RequestDefaultTypeInternal {
  PROTOBUF_CONSTEXPR GraphGet_RequestDefaultTypeInternal()
      : _instance(::_pbi::ConstantInitialized{}) {}
  ~GraphGet_RequestDefaultTypeInternal() {}
  union {
    GraphGet_Request _instance;
  };
};
PROTOBUF_ATTRIBUTE_NO_DESTROY PROTOBUF_CONSTINIT PROTOBUF_ATTRIBUTE_INIT_PRIORITY1 GraphGet_RequestDefaultTypeInternal _GraphGet_Request_default_instance_;
PROTOBUF_CONSTEXPR GraphGet_Response::GraphGet_Response(
    ::_pbi::ConstantInitialized): _impl_{
    /*decltype(_impl_._has_bits_)*/{}
  , /*decltype(_impl_._cached_size_)*/{}
  , /*decltype(_impl_.error_)*/{&::_pbi::fixed_address_empty_string, ::_pbi::ConstantInitialized{}}
  , /*decltype(_impl_.content_)*/{&::_pbi::fixed_address_empty_string, ::_pbi::ConstantInitialized{}}
  , /*decltype(_impl_.status_)*/0} {}
struct GraphGet_ResponseDefaultTypeInternal {
  PROTOBUF_CONSTEXPR GraphGet_ResponseDefaultTypeInternal()
      : _instance(::_pbi::ConstantInitialized{}) {}
  ~GraphGet_ResponseDefaultTypeInternal() {}
  union {
    GraphGet_Response _instance;
  };
};
PROTOBUF_ATTRIBUTE_NO_DESTROY PROTOBUF_CONSTINIT PROTOBUF_ATTRIBUTE_INIT_PRIORITY1 GraphGet_ResponseDefaultTypeInternal _GraphGet_Response_default_instance_;
}  // namespace graph
}  // namespace engine
}  // namespace api
}  // namespace cyb3rhq
}  // namespace com
static ::_pb::Metadata file_level_metadata_graph_2eproto[2];
static constexpr ::_pb::EnumDescriptor const** file_level_enum_descriptors_graph_2eproto = nullptr;
static constexpr ::_pb::ServiceDescriptor const** file_level_service_descriptors_graph_2eproto = nullptr;

const uint32_t TableStruct_graph_2eproto::offsets[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) = {
  PROTOBUF_FIELD_OFFSET(::com::cyb3rhq::api::engine::graph::GraphGet_Request, _impl_._has_bits_),
  PROTOBUF_FIELD_OFFSET(::com::cyb3rhq::api::engine::graph::GraphGet_Request, _internal_metadata_),
  ~0u,  // no _extensions_
  ~0u,  // no _oneof_case_
  ~0u,  // no _weak_field_map_
  ~0u,  // no _inlined_string_donated_
  PROTOBUF_FIELD_OFFSET(::com::cyb3rhq::api::engine::graph::GraphGet_Request, _impl_.policy_),
  PROTOBUF_FIELD_OFFSET(::com::cyb3rhq::api::engine::graph::GraphGet_Request, _impl_.type_),
  0,
  1,
  PROTOBUF_FIELD_OFFSET(::com::cyb3rhq::api::engine::graph::GraphGet_Response, _impl_._has_bits_),
  PROTOBUF_FIELD_OFFSET(::com::cyb3rhq::api::engine::graph::GraphGet_Response, _internal_metadata_),
  ~0u,  // no _extensions_
  ~0u,  // no _oneof_case_
  ~0u,  // no _weak_field_map_
  ~0u,  // no _inlined_string_donated_
  PROTOBUF_FIELD_OFFSET(::com::cyb3rhq::api::engine::graph::GraphGet_Response, _impl_.status_),
  PROTOBUF_FIELD_OFFSET(::com::cyb3rhq::api::engine::graph::GraphGet_Response, _impl_.error_),
  PROTOBUF_FIELD_OFFSET(::com::cyb3rhq::api::engine::graph::GraphGet_Response, _impl_.content_),
  ~0u,
  0,
  1,
};
static const ::_pbi::MigrationSchema schemas[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) = {
  { 0, 8, -1, sizeof(::com::cyb3rhq::api::engine::graph::GraphGet_Request)},
  { 10, 19, -1, sizeof(::com::cyb3rhq::api::engine::graph::GraphGet_Response)},
};

static const ::_pb::Message* const file_default_instances[] = {
  &::com::cyb3rhq::api::engine::graph::_GraphGet_Request_default_instance_._instance,
  &::com::cyb3rhq::api::engine::graph::_GraphGet_Response_default_instance_._instance,
};

const char descriptor_table_protodef_graph_2eproto[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) =
  "\n\013graph.proto\022\032com.cyb3rhq.api.engine.grap"
  "h\032\014engine.proto\"N\n\020GraphGet_Request\022\023\n\006p"
  "olicy\030\001 \001(\tH\000\210\001\001\022\021\n\004type\030\002 \001(\tH\001\210\001\001B\t\n\007_"
  "policyB\007\n\005_type\"\207\001\n\021GraphGet_Response\0222\n"
  "\006status\030\001 \001(\0162\".com.cyb3rhq.api.engine.Ret"
  "urnStatus\022\022\n\005error\030\002 \001(\tH\000\210\001\001\022\024\n\007content"
  "\030\003 \001(\tH\001\210\001\001B\010\n\006_errorB\n\n\010_contentb\006proto"
  "3"
  ;
static const ::_pbi::DescriptorTable* const descriptor_table_graph_2eproto_deps[1] = {
  &::descriptor_table_engine_2eproto,
};
static ::_pbi::once_flag descriptor_table_graph_2eproto_once;
const ::_pbi::DescriptorTable descriptor_table_graph_2eproto = {
    false, false, 281, descriptor_table_protodef_graph_2eproto,
    "graph.proto",
    &descriptor_table_graph_2eproto_once, descriptor_table_graph_2eproto_deps, 1, 2,
    schemas, file_default_instances, TableStruct_graph_2eproto::offsets,
    file_level_metadata_graph_2eproto, file_level_enum_descriptors_graph_2eproto,
    file_level_service_descriptors_graph_2eproto,
};
PROTOBUF_ATTRIBUTE_WEAK const ::_pbi::DescriptorTable* descriptor_table_graph_2eproto_getter() {
  return &descriptor_table_graph_2eproto;
}

// Force running AddDescriptors() at dynamic initialization time.
PROTOBUF_ATTRIBUTE_INIT_PRIORITY2 static ::_pbi::AddDescriptorsRunner dynamic_init_dummy_graph_2eproto(&descriptor_table_graph_2eproto);
namespace com {
namespace cyb3rhq {
namespace api {
namespace engine {
namespace graph {

// ===================================================================

class GraphGet_Request::_Internal {
 public:
  using HasBits = decltype(std::declval<GraphGet_Request>()._impl_._has_bits_);
  static void set_has_policy(HasBits* has_bits) {
    (*has_bits)[0] |= 1u;
  }
  static void set_has_type(HasBits* has_bits) {
    (*has_bits)[0] |= 2u;
  }
};

GraphGet_Request::GraphGet_Request(::PROTOBUF_NAMESPACE_ID::Arena* arena,
                         bool is_message_owned)
  : ::PROTOBUF_NAMESPACE_ID::Message(arena, is_message_owned) {
  SharedCtor(arena, is_message_owned);
  // @@protoc_insertion_point(arena_constructor:com.cyb3rhq.api.engine.graph.GraphGet_Request)
}
GraphGet_Request::GraphGet_Request(const GraphGet_Request& from)
  : ::PROTOBUF_NAMESPACE_ID::Message() {
  GraphGet_Request* const _this = this; (void)_this;
  new (&_impl_) Impl_{
      decltype(_impl_._has_bits_){from._impl_._has_bits_}
    , /*decltype(_impl_._cached_size_)*/{}
    , decltype(_impl_.policy_){}
    , decltype(_impl_.type_){}};

  _internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
  _impl_.policy_.InitDefault();
  #ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
    _impl_.policy_.Set("", GetArenaForAllocation());
  #endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
  if (from._internal_has_policy()) {
    _this->_impl_.policy_.Set(from._internal_policy(), 
      _this->GetArenaForAllocation());
  }
  _impl_.type_.InitDefault();
  #ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
    _impl_.type_.Set("", GetArenaForAllocation());
  #endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
  if (from._internal_has_type()) {
    _this->_impl_.type_.Set(from._internal_type(), 
      _this->GetArenaForAllocation());
  }
  // @@protoc_insertion_point(copy_constructor:com.cyb3rhq.api.engine.graph.GraphGet_Request)
}

inline void GraphGet_Request::SharedCtor(
    ::_pb::Arena* arena, bool is_message_owned) {
  (void)arena;
  (void)is_message_owned;
  new (&_impl_) Impl_{
      decltype(_impl_._has_bits_){}
    , /*decltype(_impl_._cached_size_)*/{}
    , decltype(_impl_.policy_){}
    , decltype(_impl_.type_){}
  };
  _impl_.policy_.InitDefault();
  #ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
    _impl_.policy_.Set("", GetArenaForAllocation());
  #endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
  _impl_.type_.InitDefault();
  #ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
    _impl_.type_.Set("", GetArenaForAllocation());
  #endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
}

GraphGet_Request::~GraphGet_Request() {
  // @@protoc_insertion_point(destructor:com.cyb3rhq.api.engine.graph.GraphGet_Request)
  if (auto *arena = _internal_metadata_.DeleteReturnArena<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>()) {
  (void)arena;
    return;
  }
  SharedDtor();
}

inline void GraphGet_Request::SharedDtor() {
  GOOGLE_DCHECK(GetArenaForAllocation() == nullptr);
  _impl_.policy_.Destroy();
  _impl_.type_.Destroy();
}

void GraphGet_Request::SetCachedSize(int size) const {
  _impl_._cached_size_.Set(size);
}

void GraphGet_Request::Clear() {
// @@protoc_insertion_point(message_clear_start:com.cyb3rhq.api.engine.graph.GraphGet_Request)
  uint32_t cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  cached_has_bits = _impl_._has_bits_[0];
  if (cached_has_bits & 0x00000003u) {
    if (cached_has_bits & 0x00000001u) {
      _impl_.policy_.ClearNonDefaultToEmpty();
    }
    if (cached_has_bits & 0x00000002u) {
      _impl_.type_.ClearNonDefaultToEmpty();
    }
  }
  _impl_._has_bits_.Clear();
  _internal_metadata_.Clear<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>();
}

const char* GraphGet_Request::_InternalParse(const char* ptr, ::_pbi::ParseContext* ctx) {
#define CHK_(x) if (PROTOBUF_PREDICT_FALSE(!(x))) goto failure
  _Internal::HasBits has_bits{};
  while (!ctx->Done(&ptr)) {
    uint32_t tag;
    ptr = ::_pbi::ReadTag(ptr, &tag);
    switch (tag >> 3) {
      // optional string policy = 1;
      case 1:
        if (PROTOBUF_PREDICT_TRUE(static_cast<uint8_t>(tag) == 10)) {
          auto str = _internal_mutable_policy();
          ptr = ::_pbi::InlineGreedyStringParser(str, ptr, ctx);
          CHK_(ptr);
          CHK_(::_pbi::VerifyUTF8(str, "com.cyb3rhq.api.engine.graph.GraphGet_Request.policy"));
        } else
          goto handle_unusual;
        continue;
      // optional string type = 2;
      case 2:
        if (PROTOBUF_PREDICT_TRUE(static_cast<uint8_t>(tag) == 18)) {
          auto str = _internal_mutable_type();
          ptr = ::_pbi::InlineGreedyStringParser(str, ptr, ctx);
          CHK_(ptr);
          CHK_(::_pbi::VerifyUTF8(str, "com.cyb3rhq.api.engine.graph.GraphGet_Request.type"));
        } else
          goto handle_unusual;
        continue;
      default:
        goto handle_unusual;
    }  // switch
  handle_unusual:
    if ((tag == 0) || ((tag & 7) == 4)) {
      CHK_(ptr);
      ctx->SetLastTag(tag);
      goto message_done;
    }
    ptr = UnknownFieldParse(
        tag,
        _internal_metadata_.mutable_unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(),
        ptr, ctx);
    CHK_(ptr != nullptr);
  }  // while
message_done:
  _impl_._has_bits_.Or(has_bits);
  return ptr;
failure:
  ptr = nullptr;
  goto message_done;
#undef CHK_
}

uint8_t* GraphGet_Request::_InternalSerialize(
    uint8_t* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const {
  // @@protoc_insertion_point(serialize_to_array_start:com.cyb3rhq.api.engine.graph.GraphGet_Request)
  uint32_t cached_has_bits = 0;
  (void) cached_has_bits;

  // optional string policy = 1;
  if (_internal_has_policy()) {
    ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::VerifyUtf8String(
      this->_internal_policy().data(), static_cast<int>(this->_internal_policy().length()),
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::SERIALIZE,
      "com.cyb3rhq.api.engine.graph.GraphGet_Request.policy");
    target = stream->WriteStringMaybeAliased(
        1, this->_internal_policy(), target);
  }

  // optional string type = 2;
  if (_internal_has_type()) {
    ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::VerifyUtf8String(
      this->_internal_type().data(), static_cast<int>(this->_internal_type().length()),
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::SERIALIZE,
      "com.cyb3rhq.api.engine.graph.GraphGet_Request.type");
    target = stream->WriteStringMaybeAliased(
        2, this->_internal_type(), target);
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    target = ::_pbi::WireFormat::InternalSerializeUnknownFieldsToArray(
        _internal_metadata_.unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(::PROTOBUF_NAMESPACE_ID::UnknownFieldSet::default_instance), target, stream);
  }
  // @@protoc_insertion_point(serialize_to_array_end:com.cyb3rhq.api.engine.graph.GraphGet_Request)
  return target;
}

size_t GraphGet_Request::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:com.cyb3rhq.api.engine.graph.GraphGet_Request)
  size_t total_size = 0;

  uint32_t cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  cached_has_bits = _impl_._has_bits_[0];
  if (cached_has_bits & 0x00000003u) {
    // optional string policy = 1;
    if (cached_has_bits & 0x00000001u) {
      total_size += 1 +
        ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::StringSize(
          this->_internal_policy());
    }

    // optional string type = 2;
    if (cached_has_bits & 0x00000002u) {
      total_size += 1 +
        ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::StringSize(
          this->_internal_type());
    }

  }
  return MaybeComputeUnknownFieldsSize(total_size, &_impl_._cached_size_);
}

const ::PROTOBUF_NAMESPACE_ID::Message::ClassData GraphGet_Request::_class_data_ = {
    ::PROTOBUF_NAMESPACE_ID::Message::CopyWithSourceCheck,
    GraphGet_Request::MergeImpl
};
const ::PROTOBUF_NAMESPACE_ID::Message::ClassData*GraphGet_Request::GetClassData() const { return &_class_data_; }


void GraphGet_Request::MergeImpl(::PROTOBUF_NAMESPACE_ID::Message& to_msg, const ::PROTOBUF_NAMESPACE_ID::Message& from_msg) {
  auto* const _this = static_cast<GraphGet_Request*>(&to_msg);
  auto& from = static_cast<const GraphGet_Request&>(from_msg);
  // @@protoc_insertion_point(class_specific_merge_from_start:com.cyb3rhq.api.engine.graph.GraphGet_Request)
  GOOGLE_DCHECK_NE(&from, _this);
  uint32_t cached_has_bits = 0;
  (void) cached_has_bits;

  cached_has_bits = from._impl_._has_bits_[0];
  if (cached_has_bits & 0x00000003u) {
    if (cached_has_bits & 0x00000001u) {
      _this->_internal_set_policy(from._internal_policy());
    }
    if (cached_has_bits & 0x00000002u) {
      _this->_internal_set_type(from._internal_type());
    }
  }
  _this->_internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
}

void GraphGet_Request::CopyFrom(const GraphGet_Request& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:com.cyb3rhq.api.engine.graph.GraphGet_Request)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool GraphGet_Request::IsInitialized() const {
  return true;
}

void GraphGet_Request::InternalSwap(GraphGet_Request* other) {
  using std::swap;
  auto* lhs_arena = GetArenaForAllocation();
  auto* rhs_arena = other->GetArenaForAllocation();
  _internal_metadata_.InternalSwap(&other->_internal_metadata_);
  swap(_impl_._has_bits_[0], other->_impl_._has_bits_[0]);
  ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::InternalSwap(
      &_impl_.policy_, lhs_arena,
      &other->_impl_.policy_, rhs_arena
  );
  ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::InternalSwap(
      &_impl_.type_, lhs_arena,
      &other->_impl_.type_, rhs_arena
  );
}

::PROTOBUF_NAMESPACE_ID::Metadata GraphGet_Request::GetMetadata() const {
  return ::_pbi::AssignDescriptors(
      &descriptor_table_graph_2eproto_getter, &descriptor_table_graph_2eproto_once,
      file_level_metadata_graph_2eproto[0]);
}

// ===================================================================

class GraphGet_Response::_Internal {
 public:
  using HasBits = decltype(std::declval<GraphGet_Response>()._impl_._has_bits_);
  static void set_has_error(HasBits* has_bits) {
    (*has_bits)[0] |= 1u;
  }
  static void set_has_content(HasBits* has_bits) {
    (*has_bits)[0] |= 2u;
  }
};

GraphGet_Response::GraphGet_Response(::PROTOBUF_NAMESPACE_ID::Arena* arena,
                         bool is_message_owned)
  : ::PROTOBUF_NAMESPACE_ID::Message(arena, is_message_owned) {
  SharedCtor(arena, is_message_owned);
  // @@protoc_insertion_point(arena_constructor:com.cyb3rhq.api.engine.graph.GraphGet_Response)
}
GraphGet_Response::GraphGet_Response(const GraphGet_Response& from)
  : ::PROTOBUF_NAMESPACE_ID::Message() {
  GraphGet_Response* const _this = this; (void)_this;
  new (&_impl_) Impl_{
      decltype(_impl_._has_bits_){from._impl_._has_bits_}
    , /*decltype(_impl_._cached_size_)*/{}
    , decltype(_impl_.error_){}
    , decltype(_impl_.content_){}
    , decltype(_impl_.status_){}};

  _internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
  _impl_.error_.InitDefault();
  #ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
    _impl_.error_.Set("", GetArenaForAllocation());
  #endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
  if (from._internal_has_error()) {
    _this->_impl_.error_.Set(from._internal_error(), 
      _this->GetArenaForAllocation());
  }
  _impl_.content_.InitDefault();
  #ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
    _impl_.content_.Set("", GetArenaForAllocation());
  #endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
  if (from._internal_has_content()) {
    _this->_impl_.content_.Set(from._internal_content(), 
      _this->GetArenaForAllocation());
  }
  _this->_impl_.status_ = from._impl_.status_;
  // @@protoc_insertion_point(copy_constructor:com.cyb3rhq.api.engine.graph.GraphGet_Response)
}

inline void GraphGet_Response::SharedCtor(
    ::_pb::Arena* arena, bool is_message_owned) {
  (void)arena;
  (void)is_message_owned;
  new (&_impl_) Impl_{
      decltype(_impl_._has_bits_){}
    , /*decltype(_impl_._cached_size_)*/{}
    , decltype(_impl_.error_){}
    , decltype(_impl_.content_){}
    , decltype(_impl_.status_){0}
  };
  _impl_.error_.InitDefault();
  #ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
    _impl_.error_.Set("", GetArenaForAllocation());
  #endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
  _impl_.content_.InitDefault();
  #ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
    _impl_.content_.Set("", GetArenaForAllocation());
  #endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
}

GraphGet_Response::~GraphGet_Response() {
  // @@protoc_insertion_point(destructor:com.cyb3rhq.api.engine.graph.GraphGet_Response)
  if (auto *arena = _internal_metadata_.DeleteReturnArena<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>()) {
  (void)arena;
    return;
  }
  SharedDtor();
}

inline void GraphGet_Response::SharedDtor() {
  GOOGLE_DCHECK(GetArenaForAllocation() == nullptr);
  _impl_.error_.Destroy();
  _impl_.content_.Destroy();
}

void GraphGet_Response::SetCachedSize(int size) const {
  _impl_._cached_size_.Set(size);
}

void GraphGet_Response::Clear() {
// @@protoc_insertion_point(message_clear_start:com.cyb3rhq.api.engine.graph.GraphGet_Response)
  uint32_t cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  cached_has_bits = _impl_._has_bits_[0];
  if (cached_has_bits & 0x00000003u) {
    if (cached_has_bits & 0x00000001u) {
      _impl_.error_.ClearNonDefaultToEmpty();
    }
    if (cached_has_bits & 0x00000002u) {
      _impl_.content_.ClearNonDefaultToEmpty();
    }
  }
  _impl_.status_ = 0;
  _impl_._has_bits_.Clear();
  _internal_metadata_.Clear<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>();
}

const char* GraphGet_Response::_InternalParse(const char* ptr, ::_pbi::ParseContext* ctx) {
#define CHK_(x) if (PROTOBUF_PREDICT_FALSE(!(x))) goto failure
  _Internal::HasBits has_bits{};
  while (!ctx->Done(&ptr)) {
    uint32_t tag;
    ptr = ::_pbi::ReadTag(ptr, &tag);
    switch (tag >> 3) {
      // .com.cyb3rhq.api.engine.ReturnStatus status = 1;
      case 1:
        if (PROTOBUF_PREDICT_TRUE(static_cast<uint8_t>(tag) == 8)) {
          uint64_t val = ::PROTOBUF_NAMESPACE_ID::internal::ReadVarint64(&ptr);
          CHK_(ptr);
          _internal_set_status(static_cast<::com::cyb3rhq::api::engine::ReturnStatus>(val));
        } else
          goto handle_unusual;
        continue;
      // optional string error = 2;
      case 2:
        if (PROTOBUF_PREDICT_TRUE(static_cast<uint8_t>(tag) == 18)) {
          auto str = _internal_mutable_error();
          ptr = ::_pbi::InlineGreedyStringParser(str, ptr, ctx);
          CHK_(ptr);
          CHK_(::_pbi::VerifyUTF8(str, "com.cyb3rhq.api.engine.graph.GraphGet_Response.error"));
        } else
          goto handle_unusual;
        continue;
      // optional string content = 3;
      case 3:
        if (PROTOBUF_PREDICT_TRUE(static_cast<uint8_t>(tag) == 26)) {
          auto str = _internal_mutable_content();
          ptr = ::_pbi::InlineGreedyStringParser(str, ptr, ctx);
          CHK_(ptr);
          CHK_(::_pbi::VerifyUTF8(str, "com.cyb3rhq.api.engine.graph.GraphGet_Response.content"));
        } else
          goto handle_unusual;
        continue;
      default:
        goto handle_unusual;
    }  // switch
  handle_unusual:
    if ((tag == 0) || ((tag & 7) == 4)) {
      CHK_(ptr);
      ctx->SetLastTag(tag);
      goto message_done;
    }
    ptr = UnknownFieldParse(
        tag,
        _internal_metadata_.mutable_unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(),
        ptr, ctx);
    CHK_(ptr != nullptr);
  }  // while
message_done:
  _impl_._has_bits_.Or(has_bits);
  return ptr;
failure:
  ptr = nullptr;
  goto message_done;
#undef CHK_
}

uint8_t* GraphGet_Response::_InternalSerialize(
    uint8_t* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const {
  // @@protoc_insertion_point(serialize_to_array_start:com.cyb3rhq.api.engine.graph.GraphGet_Response)
  uint32_t cached_has_bits = 0;
  (void) cached_has_bits;

  // .com.cyb3rhq.api.engine.ReturnStatus status = 1;
  if (this->_internal_status() != 0) {
    target = stream->EnsureSpace(target);
    target = ::_pbi::WireFormatLite::WriteEnumToArray(
      1, this->_internal_status(), target);
  }

  // optional string error = 2;
  if (_internal_has_error()) {
    ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::VerifyUtf8String(
      this->_internal_error().data(), static_cast<int>(this->_internal_error().length()),
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::SERIALIZE,
      "com.cyb3rhq.api.engine.graph.GraphGet_Response.error");
    target = stream->WriteStringMaybeAliased(
        2, this->_internal_error(), target);
  }

  // optional string content = 3;
  if (_internal_has_content()) {
    ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::VerifyUtf8String(
      this->_internal_content().data(), static_cast<int>(this->_internal_content().length()),
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::SERIALIZE,
      "com.cyb3rhq.api.engine.graph.GraphGet_Response.content");
    target = stream->WriteStringMaybeAliased(
        3, this->_internal_content(), target);
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    target = ::_pbi::WireFormat::InternalSerializeUnknownFieldsToArray(
        _internal_metadata_.unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(::PROTOBUF_NAMESPACE_ID::UnknownFieldSet::default_instance), target, stream);
  }
  // @@protoc_insertion_point(serialize_to_array_end:com.cyb3rhq.api.engine.graph.GraphGet_Response)
  return target;
}

size_t GraphGet_Response::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:com.cyb3rhq.api.engine.graph.GraphGet_Response)
  size_t total_size = 0;

  uint32_t cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  cached_has_bits = _impl_._has_bits_[0];
  if (cached_has_bits & 0x00000003u) {
    // optional string error = 2;
    if (cached_has_bits & 0x00000001u) {
      total_size += 1 +
        ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::StringSize(
          this->_internal_error());
    }

    // optional string content = 3;
    if (cached_has_bits & 0x00000002u) {
      total_size += 1 +
        ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::StringSize(
          this->_internal_content());
    }

  }
  // .com.cyb3rhq.api.engine.ReturnStatus status = 1;
  if (this->_internal_status() != 0) {
    total_size += 1 +
      ::_pbi::WireFormatLite::EnumSize(this->_internal_status());
  }

  return MaybeComputeUnknownFieldsSize(total_size, &_impl_._cached_size_);
}

const ::PROTOBUF_NAMESPACE_ID::Message::ClassData GraphGet_Response::_class_data_ = {
    ::PROTOBUF_NAMESPACE_ID::Message::CopyWithSourceCheck,
    GraphGet_Response::MergeImpl
};
const ::PROTOBUF_NAMESPACE_ID::Message::ClassData*GraphGet_Response::GetClassData() const { return &_class_data_; }


void GraphGet_Response::MergeImpl(::PROTOBUF_NAMESPACE_ID::Message& to_msg, const ::PROTOBUF_NAMESPACE_ID::Message& from_msg) {
  auto* const _this = static_cast<GraphGet_Response*>(&to_msg);
  auto& from = static_cast<const GraphGet_Response&>(from_msg);
  // @@protoc_insertion_point(class_specific_merge_from_start:com.cyb3rhq.api.engine.graph.GraphGet_Response)
  GOOGLE_DCHECK_NE(&from, _this);
  uint32_t cached_has_bits = 0;
  (void) cached_has_bits;

  cached_has_bits = from._impl_._has_bits_[0];
  if (cached_has_bits & 0x00000003u) {
    if (cached_has_bits & 0x00000001u) {
      _this->_internal_set_error(from._internal_error());
    }
    if (cached_has_bits & 0x00000002u) {
      _this->_internal_set_content(from._internal_content());
    }
  }
  if (from._internal_status() != 0) {
    _this->_internal_set_status(from._internal_status());
  }
  _this->_internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
}

void GraphGet_Response::CopyFrom(const GraphGet_Response& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:com.cyb3rhq.api.engine.graph.GraphGet_Response)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool GraphGet_Response::IsInitialized() const {
  return true;
}

void GraphGet_Response::InternalSwap(GraphGet_Response* other) {
  using std::swap;
  auto* lhs_arena = GetArenaForAllocation();
  auto* rhs_arena = other->GetArenaForAllocation();
  _internal_metadata_.InternalSwap(&other->_internal_metadata_);
  swap(_impl_._has_bits_[0], other->_impl_._has_bits_[0]);
  ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::InternalSwap(
      &_impl_.error_, lhs_arena,
      &other->_impl_.error_, rhs_arena
  );
  ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::InternalSwap(
      &_impl_.content_, lhs_arena,
      &other->_impl_.content_, rhs_arena
  );
  swap(_impl_.status_, other->_impl_.status_);
}

::PROTOBUF_NAMESPACE_ID::Metadata GraphGet_Response::GetMetadata() const {
  return ::_pbi::AssignDescriptors(
      &descriptor_table_graph_2eproto_getter, &descriptor_table_graph_2eproto_once,
      file_level_metadata_graph_2eproto[1]);
}

// @@protoc_insertion_point(namespace_scope)
}  // namespace graph
}  // namespace engine
}  // namespace api
}  // namespace cyb3rhq
}  // namespace com
PROTOBUF_NAMESPACE_OPEN
template<> PROTOBUF_NOINLINE ::com::cyb3rhq::api::engine::graph::GraphGet_Request*
Arena::CreateMaybeMessage< ::com::cyb3rhq::api::engine::graph::GraphGet_Request >(Arena* arena) {
  return Arena::CreateMessageInternal< ::com::cyb3rhq::api::engine::graph::GraphGet_Request >(arena);
}
template<> PROTOBUF_NOINLINE ::com::cyb3rhq::api::engine::graph::GraphGet_Response*
Arena::CreateMaybeMessage< ::com::cyb3rhq::api::engine::graph::GraphGet_Response >(Arena* arena) {
  return Arena::CreateMessageInternal< ::com::cyb3rhq::api::engine::graph::GraphGet_Response >(arena);
}
PROTOBUF_NAMESPACE_CLOSE

// @@protoc_insertion_point(global_scope)
#include <google/protobuf/port_undef.inc>
