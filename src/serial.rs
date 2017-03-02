// This file is generated. Do not edit
// @generated

// https://github.com/Manishearth/rust-clippy/issues/702
#![allow(unknown_lints)]
#![allow(clippy)]

#![cfg_attr(rustfmt, rustfmt_skip)]

#![allow(box_pointers)]
#![allow(dead_code)]
#![allow(missing_docs)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(trivial_casts)]
#![allow(unsafe_code)]
#![allow(unused_imports)]
#![allow(unused_results)]

use protobuf::Message as Message_imported_for_functions;
use protobuf::ProtobufEnum as ProtobufEnum_imported_for_functions;

#[derive(PartialEq,Clone,Default)]
pub struct CsrfTokenTransport {
    // message fields
    pub signature: ::std::vec::Vec<u8>,
    // message oneof groups
    body: ::std::option::Option<CsrfTokenTransport_oneof_body>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::protobuf::CachedSize,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for CsrfTokenTransport {}

#[derive(Clone,PartialEq)]
pub enum CsrfTokenTransport_oneof_body {
    encrypted_body(::std::vec::Vec<u8>),
    unencrypted_body(UnencryptedCsrfTokenTransport),
}

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
            instance.get(CsrfTokenTransport::new)
        }
    }

    // bytes encrypted_body = 1;

    pub fn clear_encrypted_body(&mut self) {
        self.body = ::std::option::Option::None;
    }

    pub fn has_encrypted_body(&self) -> bool {
        match self.body {
            ::std::option::Option::Some(CsrfTokenTransport_oneof_body::encrypted_body(..)) => true,
            _ => false,
        }
    }

    // Param is passed by value, moved
    pub fn set_encrypted_body(&mut self, v: ::std::vec::Vec<u8>) {
        self.body = ::std::option::Option::Some(CsrfTokenTransport_oneof_body::encrypted_body(v))
    }

    // Mutable pointer to the field.
    pub fn mut_encrypted_body(&mut self) -> &mut ::std::vec::Vec<u8> {
        if let ::std::option::Option::Some(CsrfTokenTransport_oneof_body::encrypted_body(_)) = self.body {
        } else {
            self.body = ::std::option::Option::Some(CsrfTokenTransport_oneof_body::encrypted_body(::std::vec::Vec::new()));
        }
        match self.body {
            ::std::option::Option::Some(CsrfTokenTransport_oneof_body::encrypted_body(ref mut v)) => v,
            _ => panic!(),
        }
    }

    // Take field
    pub fn take_encrypted_body(&mut self) -> ::std::vec::Vec<u8> {
        if self.has_encrypted_body() {
            match self.body.take() {
                ::std::option::Option::Some(CsrfTokenTransport_oneof_body::encrypted_body(v)) => v,
                _ => panic!(),
            }
        } else {
            ::std::vec::Vec::new()
        }
    }

    pub fn get_encrypted_body(&self) -> &[u8] {
        match self.body {
            ::std::option::Option::Some(CsrfTokenTransport_oneof_body::encrypted_body(ref v)) => v,
            _ => &[],
        }
    }

    // .UnencryptedCsrfTokenTransport unencrypted_body = 2;

    pub fn clear_unencrypted_body(&mut self) {
        self.body = ::std::option::Option::None;
    }

    pub fn has_unencrypted_body(&self) -> bool {
        match self.body {
            ::std::option::Option::Some(CsrfTokenTransport_oneof_body::unencrypted_body(..)) => true,
            _ => false,
        }
    }

    // Param is passed by value, moved
    pub fn set_unencrypted_body(&mut self, v: UnencryptedCsrfTokenTransport) {
        self.body = ::std::option::Option::Some(CsrfTokenTransport_oneof_body::unencrypted_body(v))
    }

    // Mutable pointer to the field.
    pub fn mut_unencrypted_body(&mut self) -> &mut UnencryptedCsrfTokenTransport {
        if let ::std::option::Option::Some(CsrfTokenTransport_oneof_body::unencrypted_body(_)) = self.body {
        } else {
            self.body = ::std::option::Option::Some(CsrfTokenTransport_oneof_body::unencrypted_body(UnencryptedCsrfTokenTransport::new()));
        }
        match self.body {
            ::std::option::Option::Some(CsrfTokenTransport_oneof_body::unencrypted_body(ref mut v)) => v,
            _ => panic!(),
        }
    }

    // Take field
    pub fn take_unencrypted_body(&mut self) -> UnencryptedCsrfTokenTransport {
        if self.has_unencrypted_body() {
            match self.body.take() {
                ::std::option::Option::Some(CsrfTokenTransport_oneof_body::unencrypted_body(v)) => v,
                _ => panic!(),
            }
        } else {
            UnencryptedCsrfTokenTransport::new()
        }
    }

    pub fn get_unencrypted_body(&self) -> &UnencryptedCsrfTokenTransport {
        match self.body {
            ::std::option::Option::Some(CsrfTokenTransport_oneof_body::unencrypted_body(ref v)) => v,
            _ => UnencryptedCsrfTokenTransport::default_instance(),
        }
    }

    // bytes signature = 3;

    pub fn clear_signature(&mut self) {
        self.signature.clear();
    }

    // Param is passed by value, moved
    pub fn set_signature(&mut self, v: ::std::vec::Vec<u8>) {
        self.signature = v;
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_signature(&mut self) -> &mut ::std::vec::Vec<u8> {
        &mut self.signature
    }

    // Take field
    pub fn take_signature(&mut self) -> ::std::vec::Vec<u8> {
        ::std::mem::replace(&mut self.signature, ::std::vec::Vec::new())
    }

    pub fn get_signature(&self) -> &[u8] {
        &self.signature
    }

    fn get_signature_for_reflect(&self) -> &::std::vec::Vec<u8> {
        &self.signature
    }

    fn mut_signature_for_reflect(&mut self) -> &mut ::std::vec::Vec<u8> {
        &mut self.signature
    }
}

impl ::protobuf::Message for CsrfTokenTransport {
    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    if wire_type != ::protobuf::wire_format::WireTypeLengthDelimited {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    };
                    self.body = ::std::option::Option::Some(CsrfTokenTransport_oneof_body::encrypted_body(is.read_bytes()?));
                },
                2 => {
                    if wire_type != ::protobuf::wire_format::WireTypeLengthDelimited {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    };
                    self.body = ::std::option::Option::Some(CsrfTokenTransport_oneof_body::unencrypted_body(is.read_message()?));
                },
                3 => {
                    ::protobuf::rt::read_singular_proto3_bytes_into(wire_type, is, &mut self.signature)?;
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if !self.signature.is_empty() {
            my_size += ::protobuf::rt::bytes_size(3, &self.signature);
        };
        if let ::std::option::Option::Some(ref v) = self.body {
            match v {
                &CsrfTokenTransport_oneof_body::encrypted_body(ref v) => {
                    my_size += ::protobuf::rt::bytes_size(1, &v);
                },
                &CsrfTokenTransport_oneof_body::unencrypted_body(ref v) => {
                    let len = v.compute_size();
                    my_size += 1 + ::protobuf::rt::compute_raw_varint32_size(len) + len;
                },
            };
        };
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        if !self.signature.is_empty() {
            os.write_bytes(3, &self.signature)?;
        };
        if let ::std::option::Option::Some(ref v) = self.body {
            match v {
                &CsrfTokenTransport_oneof_body::encrypted_body(ref v) => {
                    os.write_bytes(1, v)?;
                },
                &CsrfTokenTransport_oneof_body::unencrypted_body(ref v) => {
                    os.write_tag(2, ::protobuf::wire_format::WireTypeLengthDelimited)?;
                    os.write_raw_varint32(v.get_cached_size())?;
                    v.write_to_with_cached_sizes(os)?;
                },
            };
        };
        os.write_unknown_fields(self.get_unknown_fields())?;
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

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }
    fn as_any_mut(&mut self) -> &mut ::std::any::Any {
        self as &mut ::std::any::Any
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<::std::any::Any> {
        self
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
                fields.push(::protobuf::reflect::accessor::make_singular_bytes_accessor::<_>(
                    "encrypted_body",
                    CsrfTokenTransport::has_encrypted_body,
                    CsrfTokenTransport::get_encrypted_body,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_message_accessor::<_, UnencryptedCsrfTokenTransport>(
                    "unencrypted_body",
                    CsrfTokenTransport::has_unencrypted_body,
                    CsrfTokenTransport::get_unencrypted_body,
                ));
                fields.push(::protobuf::reflect::accessor::make_simple_field_accessor::<_, ::protobuf::types::ProtobufTypeBytes>(
                    "signature",
                    CsrfTokenTransport::get_signature_for_reflect,
                    CsrfTokenTransport::mut_signature_for_reflect,
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
        self.clear_encrypted_body();
        self.clear_unencrypted_body();
        self.clear_signature();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for CsrfTokenTransport {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for CsrfTokenTransport {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct UnencryptedCsrfTokenTransport {
    // message fields
    pub nonce: ::std::vec::Vec<u8>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::protobuf::CachedSize,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for UnencryptedCsrfTokenTransport {}

impl UnencryptedCsrfTokenTransport {
    pub fn new() -> UnencryptedCsrfTokenTransport {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static UnencryptedCsrfTokenTransport {
        static mut instance: ::protobuf::lazy::Lazy<UnencryptedCsrfTokenTransport> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const UnencryptedCsrfTokenTransport,
        };
        unsafe {
            instance.get(UnencryptedCsrfTokenTransport::new)
        }
    }

    // bytes nonce = 1;

    pub fn clear_nonce(&mut self) {
        self.nonce.clear();
    }

    // Param is passed by value, moved
    pub fn set_nonce(&mut self, v: ::std::vec::Vec<u8>) {
        self.nonce = v;
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_nonce(&mut self) -> &mut ::std::vec::Vec<u8> {
        &mut self.nonce
    }

    // Take field
    pub fn take_nonce(&mut self) -> ::std::vec::Vec<u8> {
        ::std::mem::replace(&mut self.nonce, ::std::vec::Vec::new())
    }

    pub fn get_nonce(&self) -> &[u8] {
        &self.nonce
    }

    fn get_nonce_for_reflect(&self) -> &::std::vec::Vec<u8> {
        &self.nonce
    }

    fn mut_nonce_for_reflect(&mut self) -> &mut ::std::vec::Vec<u8> {
        &mut self.nonce
    }
}

impl ::protobuf::Message for UnencryptedCsrfTokenTransport {
    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    ::protobuf::rt::read_singular_proto3_bytes_into(wire_type, is, &mut self.nonce)?;
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if !self.nonce.is_empty() {
            my_size += ::protobuf::rt::bytes_size(1, &self.nonce);
        };
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        if !self.nonce.is_empty() {
            os.write_bytes(1, &self.nonce)?;
        };
        os.write_unknown_fields(self.get_unknown_fields())?;
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

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }
    fn as_any_mut(&mut self) -> &mut ::std::any::Any {
        self as &mut ::std::any::Any
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<::std::any::Any> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for UnencryptedCsrfTokenTransport {
    fn new() -> UnencryptedCsrfTokenTransport {
        UnencryptedCsrfTokenTransport::new()
    }

    fn descriptor_static(_: ::std::option::Option<UnencryptedCsrfTokenTransport>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_simple_field_accessor::<_, ::protobuf::types::ProtobufTypeBytes>(
                    "nonce",
                    UnencryptedCsrfTokenTransport::get_nonce_for_reflect,
                    UnencryptedCsrfTokenTransport::mut_nonce_for_reflect,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<UnencryptedCsrfTokenTransport>(
                    "UnencryptedCsrfTokenTransport",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for UnencryptedCsrfTokenTransport {
    fn clear(&mut self) {
        self.clear_nonce();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for UnencryptedCsrfTokenTransport {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for UnencryptedCsrfTokenTransport {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct CsrfCookieTransport {
    // message fields
    pub signature: ::std::vec::Vec<u8>,
    // message oneof groups
    body: ::std::option::Option<CsrfCookieTransport_oneof_body>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::protobuf::CachedSize,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for CsrfCookieTransport {}

#[derive(Clone,PartialEq)]
pub enum CsrfCookieTransport_oneof_body {
    encrypted_body(::std::vec::Vec<u8>),
    unencrypted_body(UnencryptedCsrfCookieTransport),
}

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
            instance.get(CsrfCookieTransport::new)
        }
    }

    // bytes encrypted_body = 1;

    pub fn clear_encrypted_body(&mut self) {
        self.body = ::std::option::Option::None;
    }

    pub fn has_encrypted_body(&self) -> bool {
        match self.body {
            ::std::option::Option::Some(CsrfCookieTransport_oneof_body::encrypted_body(..)) => true,
            _ => false,
        }
    }

    // Param is passed by value, moved
    pub fn set_encrypted_body(&mut self, v: ::std::vec::Vec<u8>) {
        self.body = ::std::option::Option::Some(CsrfCookieTransport_oneof_body::encrypted_body(v))
    }

    // Mutable pointer to the field.
    pub fn mut_encrypted_body(&mut self) -> &mut ::std::vec::Vec<u8> {
        if let ::std::option::Option::Some(CsrfCookieTransport_oneof_body::encrypted_body(_)) = self.body {
        } else {
            self.body = ::std::option::Option::Some(CsrfCookieTransport_oneof_body::encrypted_body(::std::vec::Vec::new()));
        }
        match self.body {
            ::std::option::Option::Some(CsrfCookieTransport_oneof_body::encrypted_body(ref mut v)) => v,
            _ => panic!(),
        }
    }

    // Take field
    pub fn take_encrypted_body(&mut self) -> ::std::vec::Vec<u8> {
        if self.has_encrypted_body() {
            match self.body.take() {
                ::std::option::Option::Some(CsrfCookieTransport_oneof_body::encrypted_body(v)) => v,
                _ => panic!(),
            }
        } else {
            ::std::vec::Vec::new()
        }
    }

    pub fn get_encrypted_body(&self) -> &[u8] {
        match self.body {
            ::std::option::Option::Some(CsrfCookieTransport_oneof_body::encrypted_body(ref v)) => v,
            _ => &[],
        }
    }

    // .UnencryptedCsrfCookieTransport unencrypted_body = 2;

    pub fn clear_unencrypted_body(&mut self) {
        self.body = ::std::option::Option::None;
    }

    pub fn has_unencrypted_body(&self) -> bool {
        match self.body {
            ::std::option::Option::Some(CsrfCookieTransport_oneof_body::unencrypted_body(..)) => true,
            _ => false,
        }
    }

    // Param is passed by value, moved
    pub fn set_unencrypted_body(&mut self, v: UnencryptedCsrfCookieTransport) {
        self.body = ::std::option::Option::Some(CsrfCookieTransport_oneof_body::unencrypted_body(v))
    }

    // Mutable pointer to the field.
    pub fn mut_unencrypted_body(&mut self) -> &mut UnencryptedCsrfCookieTransport {
        if let ::std::option::Option::Some(CsrfCookieTransport_oneof_body::unencrypted_body(_)) = self.body {
        } else {
            self.body = ::std::option::Option::Some(CsrfCookieTransport_oneof_body::unencrypted_body(UnencryptedCsrfCookieTransport::new()));
        }
        match self.body {
            ::std::option::Option::Some(CsrfCookieTransport_oneof_body::unencrypted_body(ref mut v)) => v,
            _ => panic!(),
        }
    }

    // Take field
    pub fn take_unencrypted_body(&mut self) -> UnencryptedCsrfCookieTransport {
        if self.has_unencrypted_body() {
            match self.body.take() {
                ::std::option::Option::Some(CsrfCookieTransport_oneof_body::unencrypted_body(v)) => v,
                _ => panic!(),
            }
        } else {
            UnencryptedCsrfCookieTransport::new()
        }
    }

    pub fn get_unencrypted_body(&self) -> &UnencryptedCsrfCookieTransport {
        match self.body {
            ::std::option::Option::Some(CsrfCookieTransport_oneof_body::unencrypted_body(ref v)) => v,
            _ => UnencryptedCsrfCookieTransport::default_instance(),
        }
    }

    // bytes signature = 3;

    pub fn clear_signature(&mut self) {
        self.signature.clear();
    }

    // Param is passed by value, moved
    pub fn set_signature(&mut self, v: ::std::vec::Vec<u8>) {
        self.signature = v;
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_signature(&mut self) -> &mut ::std::vec::Vec<u8> {
        &mut self.signature
    }

    // Take field
    pub fn take_signature(&mut self) -> ::std::vec::Vec<u8> {
        ::std::mem::replace(&mut self.signature, ::std::vec::Vec::new())
    }

    pub fn get_signature(&self) -> &[u8] {
        &self.signature
    }

    fn get_signature_for_reflect(&self) -> &::std::vec::Vec<u8> {
        &self.signature
    }

    fn mut_signature_for_reflect(&mut self) -> &mut ::std::vec::Vec<u8> {
        &mut self.signature
    }
}

impl ::protobuf::Message for CsrfCookieTransport {
    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    if wire_type != ::protobuf::wire_format::WireTypeLengthDelimited {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    };
                    self.body = ::std::option::Option::Some(CsrfCookieTransport_oneof_body::encrypted_body(is.read_bytes()?));
                },
                2 => {
                    if wire_type != ::protobuf::wire_format::WireTypeLengthDelimited {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    };
                    self.body = ::std::option::Option::Some(CsrfCookieTransport_oneof_body::unencrypted_body(is.read_message()?));
                },
                3 => {
                    ::protobuf::rt::read_singular_proto3_bytes_into(wire_type, is, &mut self.signature)?;
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if !self.signature.is_empty() {
            my_size += ::protobuf::rt::bytes_size(3, &self.signature);
        };
        if let ::std::option::Option::Some(ref v) = self.body {
            match v {
                &CsrfCookieTransport_oneof_body::encrypted_body(ref v) => {
                    my_size += ::protobuf::rt::bytes_size(1, &v);
                },
                &CsrfCookieTransport_oneof_body::unencrypted_body(ref v) => {
                    let len = v.compute_size();
                    my_size += 1 + ::protobuf::rt::compute_raw_varint32_size(len) + len;
                },
            };
        };
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        if !self.signature.is_empty() {
            os.write_bytes(3, &self.signature)?;
        };
        if let ::std::option::Option::Some(ref v) = self.body {
            match v {
                &CsrfCookieTransport_oneof_body::encrypted_body(ref v) => {
                    os.write_bytes(1, v)?;
                },
                &CsrfCookieTransport_oneof_body::unencrypted_body(ref v) => {
                    os.write_tag(2, ::protobuf::wire_format::WireTypeLengthDelimited)?;
                    os.write_raw_varint32(v.get_cached_size())?;
                    v.write_to_with_cached_sizes(os)?;
                },
            };
        };
        os.write_unknown_fields(self.get_unknown_fields())?;
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

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }
    fn as_any_mut(&mut self) -> &mut ::std::any::Any {
        self as &mut ::std::any::Any
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<::std::any::Any> {
        self
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
                fields.push(::protobuf::reflect::accessor::make_singular_bytes_accessor::<_>(
                    "encrypted_body",
                    CsrfCookieTransport::has_encrypted_body,
                    CsrfCookieTransport::get_encrypted_body,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_message_accessor::<_, UnencryptedCsrfCookieTransport>(
                    "unencrypted_body",
                    CsrfCookieTransport::has_unencrypted_body,
                    CsrfCookieTransport::get_unencrypted_body,
                ));
                fields.push(::protobuf::reflect::accessor::make_simple_field_accessor::<_, ::protobuf::types::ProtobufTypeBytes>(
                    "signature",
                    CsrfCookieTransport::get_signature_for_reflect,
                    CsrfCookieTransport::mut_signature_for_reflect,
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
        self.clear_encrypted_body();
        self.clear_unencrypted_body();
        self.clear_signature();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for CsrfCookieTransport {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for CsrfCookieTransport {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct UnencryptedCsrfCookieTransport {
    // message fields
    pub expires: u64,
    pub nonce: ::std::vec::Vec<u8>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::protobuf::CachedSize,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for UnencryptedCsrfCookieTransport {}

impl UnencryptedCsrfCookieTransport {
    pub fn new() -> UnencryptedCsrfCookieTransport {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static UnencryptedCsrfCookieTransport {
        static mut instance: ::protobuf::lazy::Lazy<UnencryptedCsrfCookieTransport> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const UnencryptedCsrfCookieTransport,
        };
        unsafe {
            instance.get(UnencryptedCsrfCookieTransport::new)
        }
    }

    // uint64 expires = 1;

    pub fn clear_expires(&mut self) {
        self.expires = 0;
    }

    // Param is passed by value, moved
    pub fn set_expires(&mut self, v: u64) {
        self.expires = v;
    }

    pub fn get_expires(&self) -> u64 {
        self.expires
    }

    fn get_expires_for_reflect(&self) -> &u64 {
        &self.expires
    }

    fn mut_expires_for_reflect(&mut self) -> &mut u64 {
        &mut self.expires
    }

    // bytes nonce = 2;

    pub fn clear_nonce(&mut self) {
        self.nonce.clear();
    }

    // Param is passed by value, moved
    pub fn set_nonce(&mut self, v: ::std::vec::Vec<u8>) {
        self.nonce = v;
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_nonce(&mut self) -> &mut ::std::vec::Vec<u8> {
        &mut self.nonce
    }

    // Take field
    pub fn take_nonce(&mut self) -> ::std::vec::Vec<u8> {
        ::std::mem::replace(&mut self.nonce, ::std::vec::Vec::new())
    }

    pub fn get_nonce(&self) -> &[u8] {
        &self.nonce
    }

    fn get_nonce_for_reflect(&self) -> &::std::vec::Vec<u8> {
        &self.nonce
    }

    fn mut_nonce_for_reflect(&mut self) -> &mut ::std::vec::Vec<u8> {
        &mut self.nonce
    }
}

impl ::protobuf::Message for UnencryptedCsrfCookieTransport {
    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    };
                    let tmp = is.read_uint64()?;
                    self.expires = tmp;
                },
                2 => {
                    ::protobuf::rt::read_singular_proto3_bytes_into(wire_type, is, &mut self.nonce)?;
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if self.expires != 0 {
            my_size += ::protobuf::rt::value_size(1, self.expires, ::protobuf::wire_format::WireTypeVarint);
        };
        if !self.nonce.is_empty() {
            my_size += ::protobuf::rt::bytes_size(2, &self.nonce);
        };
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        if self.expires != 0 {
            os.write_uint64(1, self.expires)?;
        };
        if !self.nonce.is_empty() {
            os.write_bytes(2, &self.nonce)?;
        };
        os.write_unknown_fields(self.get_unknown_fields())?;
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

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }
    fn as_any_mut(&mut self) -> &mut ::std::any::Any {
        self as &mut ::std::any::Any
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<::std::any::Any> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for UnencryptedCsrfCookieTransport {
    fn new() -> UnencryptedCsrfCookieTransport {
        UnencryptedCsrfCookieTransport::new()
    }

    fn descriptor_static(_: ::std::option::Option<UnencryptedCsrfCookieTransport>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_simple_field_accessor::<_, ::protobuf::types::ProtobufTypeUint64>(
                    "expires",
                    UnencryptedCsrfCookieTransport::get_expires_for_reflect,
                    UnencryptedCsrfCookieTransport::mut_expires_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_simple_field_accessor::<_, ::protobuf::types::ProtobufTypeBytes>(
                    "nonce",
                    UnencryptedCsrfCookieTransport::get_nonce_for_reflect,
                    UnencryptedCsrfCookieTransport::mut_nonce_for_reflect,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<UnencryptedCsrfCookieTransport>(
                    "UnencryptedCsrfCookieTransport",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for UnencryptedCsrfCookieTransport {
    fn clear(&mut self) {
        self.clear_expires();
        self.clear_nonce();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for UnencryptedCsrfCookieTransport {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for UnencryptedCsrfCookieTransport {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

static file_descriptor_proto_data: &'static [u8] = &[
    0x0a, 0x12, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x73, 0x65, 0x72, 0x69, 0x61, 0x6c, 0x2e, 0x70,
    0x72, 0x6f, 0x74, 0x6f, 0x22, 0xb0, 0x01, 0x0a, 0x12, 0x43, 0x73, 0x72, 0x66, 0x54, 0x6f, 0x6b,
    0x65, 0x6e, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x12, 0x27, 0x0a, 0x0e, 0x65,
    0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x5f, 0x62, 0x6f, 0x64, 0x79, 0x18, 0x01, 0x20,
    0x01, 0x28, 0x0c, 0x48, 0x00, 0x52, 0x0d, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64,
    0x42, 0x6f, 0x64, 0x79, 0x12, 0x4b, 0x0a, 0x10, 0x75, 0x6e, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70,
    0x74, 0x65, 0x64, 0x5f, 0x62, 0x6f, 0x64, 0x79, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1e,
    0x2e, 0x55, 0x6e, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x43, 0x73, 0x72, 0x66,
    0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x48, 0x00,
    0x52, 0x0f, 0x75, 0x6e, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x42, 0x6f, 0x64,
    0x79, 0x12, 0x1c, 0x0a, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x18, 0x03,
    0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x42,
    0x06, 0x0a, 0x04, 0x62, 0x6f, 0x64, 0x79, 0x22, 0x35, 0x0a, 0x1d, 0x55, 0x6e, 0x65, 0x6e, 0x63,
    0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x43, 0x73, 0x72, 0x66, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x54,
    0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x12, 0x14, 0x0a, 0x05, 0x6e, 0x6f, 0x6e, 0x63,
    0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x05, 0x6e, 0x6f, 0x6e, 0x63, 0x65, 0x22, 0xb2,
    0x01, 0x0a, 0x13, 0x43, 0x73, 0x72, 0x66, 0x43, 0x6f, 0x6f, 0x6b, 0x69, 0x65, 0x54, 0x72, 0x61,
    0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x12, 0x27, 0x0a, 0x0e, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70,
    0x74, 0x65, 0x64, 0x5f, 0x62, 0x6f, 0x64, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x48, 0x00,
    0x52, 0x0d, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x42, 0x6f, 0x64, 0x79, 0x12,
    0x4c, 0x0a, 0x10, 0x75, 0x6e, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x5f, 0x62,
    0x6f, 0x64, 0x79, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1f, 0x2e, 0x55, 0x6e, 0x65, 0x6e,
    0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x43, 0x73, 0x72, 0x66, 0x43, 0x6f, 0x6f, 0x6b, 0x69,
    0x65, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x48, 0x00, 0x52, 0x0f, 0x75, 0x6e,
    0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x42, 0x6f, 0x64, 0x79, 0x12, 0x1c, 0x0a,
    0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c,
    0x52, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x42, 0x06, 0x0a, 0x04, 0x62,
    0x6f, 0x64, 0x79, 0x22, 0x50, 0x0a, 0x1e, 0x55, 0x6e, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74,
    0x65, 0x64, 0x43, 0x73, 0x72, 0x66, 0x43, 0x6f, 0x6f, 0x6b, 0x69, 0x65, 0x54, 0x72, 0x61, 0x6e,
    0x73, 0x70, 0x6f, 0x72, 0x74, 0x12, 0x18, 0x0a, 0x07, 0x65, 0x78, 0x70, 0x69, 0x72, 0x65, 0x73,
    0x18, 0x01, 0x20, 0x01, 0x28, 0x04, 0x52, 0x07, 0x65, 0x78, 0x70, 0x69, 0x72, 0x65, 0x73, 0x12,
    0x14, 0x0a, 0x05, 0x6e, 0x6f, 0x6e, 0x63, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x05,
    0x6e, 0x6f, 0x6e, 0x63, 0x65, 0x4a, 0xe4, 0x05, 0x0a, 0x06, 0x12, 0x04, 0x00, 0x00, 0x19, 0x01,
    0x0a, 0x08, 0x0a, 0x01, 0x0c, 0x12, 0x03, 0x00, 0x00, 0x12, 0x0a, 0x0a, 0x0a, 0x02, 0x04, 0x00,
    0x12, 0x04, 0x02, 0x00, 0x08, 0x01, 0x0a, 0x0a, 0x0a, 0x03, 0x04, 0x00, 0x01, 0x12, 0x03, 0x02,
    0x08, 0x1a, 0x0a, 0x0c, 0x0a, 0x04, 0x04, 0x00, 0x08, 0x00, 0x12, 0x04, 0x03, 0x04, 0x06, 0x05,
    0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x00, 0x08, 0x00, 0x01, 0x12, 0x03, 0x03, 0x0a, 0x0e, 0x0a, 0x0b,
    0x0a, 0x04, 0x04, 0x00, 0x02, 0x00, 0x12, 0x03, 0x04, 0x08, 0x3b, 0x0a, 0x0c, 0x0a, 0x05, 0x04,
    0x00, 0x02, 0x00, 0x05, 0x12, 0x03, 0x04, 0x08, 0x0d, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x00, 0x02,
    0x00, 0x01, 0x12, 0x03, 0x04, 0x26, 0x34, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x00, 0x02, 0x00, 0x03,
    0x12, 0x03, 0x04, 0x39, 0x3a, 0x0a, 0x0b, 0x0a, 0x04, 0x04, 0x00, 0x02, 0x01, 0x12, 0x03, 0x05,
    0x08, 0x3b, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x00, 0x02, 0x01, 0x06, 0x12, 0x03, 0x05, 0x08, 0x25,
    0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x00, 0x02, 0x01, 0x01, 0x12, 0x03, 0x05, 0x26, 0x36, 0x0a, 0x0c,
    0x0a, 0x05, 0x04, 0x00, 0x02, 0x01, 0x03, 0x12, 0x03, 0x05, 0x39, 0x3a, 0x0a, 0x0b, 0x0a, 0x04,
    0x04, 0x00, 0x02, 0x02, 0x12, 0x03, 0x07, 0x04, 0x3b, 0x0a, 0x0d, 0x0a, 0x05, 0x04, 0x00, 0x02,
    0x02, 0x04, 0x12, 0x04, 0x07, 0x04, 0x06, 0x05, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x00, 0x02, 0x02,
    0x05, 0x12, 0x03, 0x07, 0x04, 0x09, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x00, 0x02, 0x02, 0x01, 0x12,
    0x03, 0x07, 0x26, 0x2f, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x00, 0x02, 0x02, 0x03, 0x12, 0x03, 0x07,
    0x39, 0x3a, 0x0a, 0x0a, 0x0a, 0x02, 0x04, 0x01, 0x12, 0x04, 0x0a, 0x00, 0x0c, 0x01, 0x0a, 0x0a,
    0x0a, 0x03, 0x04, 0x01, 0x01, 0x12, 0x03, 0x0a, 0x08, 0x25, 0x0a, 0x0b, 0x0a, 0x04, 0x04, 0x01,
    0x02, 0x00, 0x12, 0x03, 0x0b, 0x04, 0x14, 0x0a, 0x0d, 0x0a, 0x05, 0x04, 0x01, 0x02, 0x00, 0x04,
    0x12, 0x04, 0x0b, 0x04, 0x0a, 0x27, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x01, 0x02, 0x00, 0x05, 0x12,
    0x03, 0x0b, 0x04, 0x09, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x01, 0x02, 0x00, 0x01, 0x12, 0x03, 0x0b,
    0x0a, 0x0f, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x01, 0x02, 0x00, 0x03, 0x12, 0x03, 0x0b, 0x12, 0x13,
    0x0a, 0x0a, 0x0a, 0x02, 0x04, 0x02, 0x12, 0x04, 0x0e, 0x00, 0x14, 0x01, 0x0a, 0x0a, 0x0a, 0x03,
    0x04, 0x02, 0x01, 0x12, 0x03, 0x0e, 0x08, 0x1b, 0x0a, 0x0c, 0x0a, 0x04, 0x04, 0x02, 0x08, 0x00,
    0x12, 0x04, 0x0f, 0x04, 0x12, 0x05, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x02, 0x08, 0x00, 0x01, 0x12,
    0x03, 0x0f, 0x0a, 0x0e, 0x0a, 0x0b, 0x0a, 0x04, 0x04, 0x02, 0x02, 0x00, 0x12, 0x03, 0x10, 0x08,
    0x3c, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x02, 0x02, 0x00, 0x05, 0x12, 0x03, 0x10, 0x08, 0x0d, 0x0a,
    0x0c, 0x0a, 0x05, 0x04, 0x02, 0x02, 0x00, 0x01, 0x12, 0x03, 0x10, 0x27, 0x35, 0x0a, 0x0c, 0x0a,
    0x05, 0x04, 0x02, 0x02, 0x00, 0x03, 0x12, 0x03, 0x10, 0x3a, 0x3b, 0x0a, 0x0b, 0x0a, 0x04, 0x04,
    0x02, 0x02, 0x01, 0x12, 0x03, 0x11, 0x08, 0x3c, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x02, 0x02, 0x01,
    0x06, 0x12, 0x03, 0x11, 0x08, 0x26, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x02, 0x02, 0x01, 0x01, 0x12,
    0x03, 0x11, 0x27, 0x37, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x02, 0x02, 0x01, 0x03, 0x12, 0x03, 0x11,
    0x3a, 0x3b, 0x0a, 0x0b, 0x0a, 0x04, 0x04, 0x02, 0x02, 0x02, 0x12, 0x03, 0x13, 0x04, 0x3c, 0x0a,
    0x0d, 0x0a, 0x05, 0x04, 0x02, 0x02, 0x02, 0x04, 0x12, 0x04, 0x13, 0x04, 0x12, 0x05, 0x0a, 0x0c,
    0x0a, 0x05, 0x04, 0x02, 0x02, 0x02, 0x05, 0x12, 0x03, 0x13, 0x04, 0x09, 0x0a, 0x0c, 0x0a, 0x05,
    0x04, 0x02, 0x02, 0x02, 0x01, 0x12, 0x03, 0x13, 0x27, 0x30, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x02,
    0x02, 0x02, 0x03, 0x12, 0x03, 0x13, 0x3a, 0x3b, 0x0a, 0x0a, 0x0a, 0x02, 0x04, 0x03, 0x12, 0x04,
    0x16, 0x00, 0x19, 0x01, 0x0a, 0x0a, 0x0a, 0x03, 0x04, 0x03, 0x01, 0x12, 0x03, 0x16, 0x08, 0x26,
    0x0a, 0x0b, 0x0a, 0x04, 0x04, 0x03, 0x02, 0x00, 0x12, 0x03, 0x17, 0x04, 0x19, 0x0a, 0x0d, 0x0a,
    0x05, 0x04, 0x03, 0x02, 0x00, 0x04, 0x12, 0x04, 0x17, 0x04, 0x16, 0x28, 0x0a, 0x0c, 0x0a, 0x05,
    0x04, 0x03, 0x02, 0x00, 0x05, 0x12, 0x03, 0x17, 0x04, 0x0a, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x03,
    0x02, 0x00, 0x01, 0x12, 0x03, 0x17, 0x0b, 0x12, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x03, 0x02, 0x00,
    0x03, 0x12, 0x03, 0x17, 0x17, 0x18, 0x0a, 0x0b, 0x0a, 0x04, 0x04, 0x03, 0x02, 0x01, 0x12, 0x03,
    0x18, 0x04, 0x19, 0x0a, 0x0d, 0x0a, 0x05, 0x04, 0x03, 0x02, 0x01, 0x04, 0x12, 0x04, 0x18, 0x04,
    0x17, 0x19, 0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x03, 0x02, 0x01, 0x05, 0x12, 0x03, 0x18, 0x04, 0x09,
    0x0a, 0x0c, 0x0a, 0x05, 0x04, 0x03, 0x02, 0x01, 0x01, 0x12, 0x03, 0x18, 0x0b, 0x10, 0x0a, 0x0c,
    0x0a, 0x05, 0x04, 0x03, 0x02, 0x01, 0x03, 0x12, 0x03, 0x18, 0x17, 0x18, 0x62, 0x06, 0x70, 0x72,
    0x6f, 0x74, 0x6f, 0x33,
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
