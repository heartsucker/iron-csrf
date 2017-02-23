// This file is generated. Do not edit
// @generated

// https://github.com/Manishearth/rust-clippy/issues/702
#![allow(unknown_lints)]
#![allow(clippy)]

#![cfg_attr(rustfmt, rustfmt_skip)]

#![allow(box_pointers)]
#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(trivial_casts)]
#![allow(unsafe_code)]
#![allow(unused_imports)]
#![allow(unused_results)]

use protobuf::Message as Message_imported_for_functions;
use protobuf::ProtobufEnum as ProtobufEnum_imported_for_functions;

#[derive(Clone,Default)]
pub struct CsrfTokenTransport {
    // message fields
    nonce: ::protobuf::SingularField<::std::vec::Vec<u8>>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::std::cell::Cell<u32>,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for CsrfTokenTransport {}

impl CsrfTokenTransport {
    pub fn new() -> CsrfTokenTransport {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static CsrfTokenTransport {
        static mut instance: ::protobuf::lazy::Lazy<CsrfTokenTransport> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const CsrfTokenTransport,
        };
        unsafe {
            instance.get(|| {
                CsrfTokenTransport {
                    nonce: ::protobuf::SingularField::none(),
                    unknown_fields: ::protobuf::UnknownFields::new(),
                    cached_size: ::std::cell::Cell::new(0),
                }
            })
        }
    }

    // optional bytes nonce = 1;

    pub fn clear_nonce(&mut self) {
        self.nonce.clear();
    }

    pub fn has_nonce(&self) -> bool {
        self.nonce.is_some()
    }

    // Param is passed by value, moved
    pub fn set_nonce(&mut self, v: ::std::vec::Vec<u8>) {
        self.nonce = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_nonce(&mut self) -> &mut ::std::vec::Vec<u8> {
        if self.nonce.is_none() {
            self.nonce.set_default();
        };
        self.nonce.as_mut().unwrap()
    }

    // Take field
    pub fn take_nonce(&mut self) -> ::std::vec::Vec<u8> {
        self.nonce.take().unwrap_or_else(|| ::std::vec::Vec::new())
    }

    pub fn get_nonce(&self) -> &[u8] {
        match self.nonce.as_ref() {
            Some(v) => &v,
            None => &[],
        }
    }
}

impl ::protobuf::Message for CsrfTokenTransport {
    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !try!(is.eof()) {
            let (field_number, wire_type) = try!(is.read_tag_unpack());
            match field_number {
                1 => {
                    try!(::protobuf::rt::read_singular_bytes_into(wire_type, is, &mut self.nonce));
                },
                _ => {
                    try!(::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields()));
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        for value in &self.nonce {
            my_size += ::protobuf::rt::bytes_size(1, &value);
        };
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        if let Some(v) = self.nonce.as_ref() {
            try!(os.write_bytes(1, &v));
        };
        try!(os.write_unknown_fields(self.get_unknown_fields()));
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn type_id(&self) -> ::std::any::TypeId {
        ::std::any::TypeId::of::<CsrfTokenTransport>()
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for CsrfTokenTransport {
    fn new() -> CsrfTokenTransport {
        CsrfTokenTransport::new()
    }

    fn descriptor_static(_: ::std::option::Option<CsrfTokenTransport>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_singular_bytes_accessor(
                    "nonce",
                    CsrfTokenTransport::has_nonce,
                    CsrfTokenTransport::get_nonce,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<CsrfTokenTransport>(
                    "CsrfTokenTransport",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for CsrfTokenTransport {
    fn clear(&mut self) {
        self.clear_nonce();
        self.unknown_fields.clear();
    }
}

impl ::std::cmp::PartialEq for CsrfTokenTransport {
    fn eq(&self, other: &CsrfTokenTransport) -> bool {
        self.nonce == other.nonce &&
        self.unknown_fields == other.unknown_fields
    }
}

impl ::std::fmt::Debug for CsrfTokenTransport {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

#[derive(Clone,Default)]
pub struct CsrfCookieTransport {
    // message fields
    expires: ::std::option::Option<u64>,
    nonce: ::protobuf::SingularField<::std::vec::Vec<u8>>,
    signature: ::protobuf::SingularField<::std::vec::Vec<u8>>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::std::cell::Cell<u32>,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for CsrfCookieTransport {}

impl CsrfCookieTransport {
    pub fn new() -> CsrfCookieTransport {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static CsrfCookieTransport {
        static mut instance: ::protobuf::lazy::Lazy<CsrfCookieTransport> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const CsrfCookieTransport,
        };
        unsafe {
            instance.get(|| {
                CsrfCookieTransport {
                    expires: ::std::option::Option::None,
                    nonce: ::protobuf::SingularField::none(),
                    signature: ::protobuf::SingularField::none(),
                    unknown_fields: ::protobuf::UnknownFields::new(),
                    cached_size: ::std::cell::Cell::new(0),
                }
            })
        }
    }

    // optional uint64 expires = 1;

    pub fn clear_expires(&mut self) {
        self.expires = ::std::option::Option::None;
    }

    pub fn has_expires(&self) -> bool {
        self.expires.is_some()
    }

    // Param is passed by value, moved
    pub fn set_expires(&mut self, v: u64) {
        self.expires = ::std::option::Option::Some(v);
    }

    pub fn get_expires(&self) -> u64 {
        self.expires.unwrap_or(0)
    }

    // optional bytes nonce = 2;

    pub fn clear_nonce(&mut self) {
        self.nonce.clear();
    }

    pub fn has_nonce(&self) -> bool {
        self.nonce.is_some()
    }

    // Param is passed by value, moved
    pub fn set_nonce(&mut self, v: ::std::vec::Vec<u8>) {
        self.nonce = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_nonce(&mut self) -> &mut ::std::vec::Vec<u8> {
        if self.nonce.is_none() {
            self.nonce.set_default();
        };
        self.nonce.as_mut().unwrap()
    }

    // Take field
    pub fn take_nonce(&mut self) -> ::std::vec::Vec<u8> {
        self.nonce.take().unwrap_or_else(|| ::std::vec::Vec::new())
    }

    pub fn get_nonce(&self) -> &[u8] {
        match self.nonce.as_ref() {
            Some(v) => &v,
            None => &[],
        }
    }

    // optional bytes signature = 3;

    pub fn clear_signature(&mut self) {
        self.signature.clear();
    }

    pub fn has_signature(&self) -> bool {
        self.signature.is_some()
    }

    // Param is passed by value, moved
    pub fn set_signature(&mut self, v: ::std::vec::Vec<u8>) {
        self.signature = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_signature(&mut self) -> &mut ::std::vec::Vec<u8> {
        if self.signature.is_none() {
            self.signature.set_default();
        };
        self.signature.as_mut().unwrap()
    }

    // Take field
    pub fn take_signature(&mut self) -> ::std::vec::Vec<u8> {
        self.signature.take().unwrap_or_else(|| ::std::vec::Vec::new())
    }

    pub fn get_signature(&self) -> &[u8] {
        match self.signature.as_ref() {
            Some(v) => &v,
            None => &[],
        }
    }
}

impl ::protobuf::Message for CsrfCookieTransport {
    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !try!(is.eof()) {
            let (field_number, wire_type) = try!(is.read_tag_unpack());
            match field_number {
                1 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    };
                    let tmp = try!(is.read_uint64());
                    self.expires = ::std::option::Option::Some(tmp);
                },
                2 => {
                    try!(::protobuf::rt::read_singular_bytes_into(wire_type, is, &mut self.nonce));
                },
                3 => {
                    try!(::protobuf::rt::read_singular_bytes_into(wire_type, is, &mut self.signature));
                },
                _ => {
                    try!(::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields()));
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        for value in &self.expires {
            my_size += ::protobuf::rt::value_size(1, *value, ::protobuf::wire_format::WireTypeVarint);
        };
        for value in &self.nonce {
            my_size += ::protobuf::rt::bytes_size(2, &value);
        };
        for value in &self.signature {
            my_size += ::protobuf::rt::bytes_size(3, &value);
        };
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        if let Some(v) = self.expires {
            try!(os.write_uint64(1, v));
        };
        if let Some(v) = self.nonce.as_ref() {
            try!(os.write_bytes(2, &v));
        };
        if let Some(v) = self.signature.as_ref() {
            try!(os.write_bytes(3, &v));
        };
        try!(os.write_unknown_fields(self.get_unknown_fields()));
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn type_id(&self) -> ::std::any::TypeId {
        ::std::any::TypeId::of::<CsrfCookieTransport>()
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for CsrfCookieTransport {
    fn new() -> CsrfCookieTransport {
        CsrfCookieTransport::new()
    }

    fn descriptor_static(_: ::std::option::Option<CsrfCookieTransport>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_singular_u64_accessor(
                    "expires",
                    CsrfCookieTransport::has_expires,
                    CsrfCookieTransport::get_expires,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_bytes_accessor(
                    "nonce",
                    CsrfCookieTransport::has_nonce,
                    CsrfCookieTransport::get_nonce,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_bytes_accessor(
                    "signature",
                    CsrfCookieTransport::has_signature,
                    CsrfCookieTransport::get_signature,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<CsrfCookieTransport>(
                    "CsrfCookieTransport",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for CsrfCookieTransport {
    fn clear(&mut self) {
        self.clear_expires();
        self.clear_nonce();
        self.clear_signature();
        self.unknown_fields.clear();
    }
}

impl ::std::cmp::PartialEq for CsrfCookieTransport {
    fn eq(&self, other: &CsrfCookieTransport) -> bool {
        self.expires == other.expires &&
        self.nonce == other.nonce &&
        self.signature == other.signature &&
        self.unknown_fields == other.unknown_fields
    }
}

impl ::std::fmt::Debug for CsrfCookieTransport {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

static file_descriptor_proto_data: &'static [u8] = &[
    0x0a, 0x12, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x73, 0x65, 0x72, 0x69, 0x61, 0x6c, 0x2e, 0x70,
    0x72, 0x6f, 0x74, 0x6f, 0x22, 0x2a, 0x0a, 0x12, 0x43, 0x73, 0x72, 0x66, 0x54, 0x6f, 0x6b, 0x65,
    0x6e, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x12, 0x14, 0x0a, 0x05, 0x6e, 0x6f,
    0x6e, 0x63, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x05, 0x6e, 0x6f, 0x6e, 0x63, 0x65,
    0x22, 0x63, 0x0a, 0x13, 0x43, 0x73, 0x72, 0x66, 0x43, 0x6f, 0x6f, 0x6b, 0x69, 0x65, 0x54, 0x72,
    0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x12, 0x18, 0x0a, 0x07, 0x65, 0x78, 0x70, 0x69, 0x72,
    0x65, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x04, 0x52, 0x07, 0x65, 0x78, 0x70, 0x69, 0x72, 0x65,
    0x73, 0x12, 0x14, 0x0a, 0x05, 0x6e, 0x6f, 0x6e, 0x63, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c,
    0x52, 0x05, 0x6e, 0x6f, 0x6e, 0x63, 0x65, 0x12, 0x1c, 0x0a, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61,
    0x74, 0x75, 0x72, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x73, 0x69, 0x67, 0x6e,
    0x61, 0x74, 0x75, 0x72, 0x65, 0x4a, 0xda, 0x02, 0x0a, 0x06, 0x12, 0x04, 0x00, 0x00, 0x0a, 0x01,
    0x0a, 0x08, 0x0a, 0x01, 0x0c, 0x12, 0x03, 0x00, 0x00, 0x12, 0x0a, 0x0a, 0x0a, 0x02, 0x04, 0x00,
    0x12, 0x04, 0x02, 0x00, 0x04, 0x01, 0x0a, 0x0a, 0x0a, 0x03, 0x04, 0x00, 0x01, 0x12, 0x03, 0x02,
    0x08, 0x1a, 0x0a, 0x0b, 0x0a, 0x04, 0x04, 0x00, 0x02, 0x00, 0x12, 0x03, 0x03, 0x04, 0x14, 0x0a,
    0x0d, 0x0a, 0x05, 0x04, 0x00, 0x02, 0x00, 0x04, 0x12, 0x04, 0x03, 0x04, 0x02, 0x1c, 0x0a, 0x0c,
    0x0a, 0x05, 0x04, 0x00, 0x02, 0x00, 0x05, 0x12, 0x03, 0x03, 0x04, 0x09, 0x0a, 0x0c, 0x0a, 0x05,
    0x04, 0x00, 0x02, 0x00, 0x01, 0x12, 0x03, 0x03, 0x0a, 0x0f, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x00,
    0x02, 0x00, 0x03, 0x12, 0x03, 0x03, 0x12, 0x13, 0x0a, 0x0a, 0x0a, 0x02, 0x04, 0x01, 0x12, 0x04,
    0x06, 0x00, 0x0a, 0x01, 0x0a, 0x0a, 0x0a, 0x03, 0x04, 0x01, 0x01, 0x12, 0x03, 0x06, 0x08, 0x1b,
    0x0a, 0x0b, 0x0a, 0x04, 0x04, 0x01, 0x02, 0x00, 0x12, 0x03, 0x07, 0x04, 0x19, 0x0a, 0x0d, 0x0a,
    0x05, 0x04, 0x01, 0x02, 0x00, 0x04, 0x12, 0x04, 0x07, 0x04, 0x06, 0x1d, 0x0a, 0x0c, 0x0a, 0x05,
    0x04, 0x01, 0x02, 0x00, 0x05, 0x12, 0x03, 0x07, 0x04, 0x0a, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x01,
    0x02, 0x00, 0x01, 0x12, 0x03, 0x07, 0x0b, 0x12, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x01, 0x02, 0x00,
    0x03, 0x12, 0x03, 0x07, 0x17, 0x18, 0x0a, 0x0b, 0x0a, 0x04, 0x04, 0x01, 0x02, 0x01, 0x12, 0x03,
    0x08, 0x04, 0x19, 0x0a, 0x0d, 0x0a, 0x05, 0x04, 0x01, 0x02, 0x01, 0x04, 0x12, 0x04, 0x08, 0x04,
    0x07, 0x19, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x01, 0x02, 0x01, 0x05, 0x12, 0x03, 0x08, 0x04, 0x09,
    0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x01, 0x02, 0x01, 0x01, 0x12, 0x03, 0x08, 0x0b, 0x10, 0x0a, 0x0c,
    0x0a, 0x05, 0x04, 0x01, 0x02, 0x01, 0x03, 0x12, 0x03, 0x08, 0x17, 0x18, 0x0a, 0x0b, 0x0a, 0x04,
    0x04, 0x01, 0x02, 0x02, 0x12, 0x03, 0x09, 0x04, 0x19, 0x0a, 0x0d, 0x0a, 0x05, 0x04, 0x01, 0x02,
    0x02, 0x04, 0x12, 0x04, 0x09, 0x04, 0x08, 0x19, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x01, 0x02, 0x02,
    0x05, 0x12, 0x03, 0x09, 0x04, 0x09, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x01, 0x02, 0x02, 0x01, 0x12,
    0x03, 0x09, 0x0b, 0x14, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x01, 0x02, 0x02, 0x03, 0x12, 0x03, 0x09,
    0x17, 0x18, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
];

static mut file_descriptor_proto_lazy: ::protobuf::lazy::Lazy<::protobuf::descriptor::FileDescriptorProto> = ::protobuf::lazy::Lazy {
    lock: ::protobuf::lazy::ONCE_INIT,
    ptr: 0 as *const ::protobuf::descriptor::FileDescriptorProto,
};

fn parse_descriptor_proto() -> ::protobuf::descriptor::FileDescriptorProto {
    ::protobuf::parse_from_bytes(file_descriptor_proto_data).unwrap()
}

pub fn file_descriptor_proto() -> &'static ::protobuf::descriptor::FileDescriptorProto {
    unsafe {
        file_descriptor_proto_lazy.get(|| {
            parse_descriptor_proto()
        })
    }
}
