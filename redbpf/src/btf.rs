// Copyright 2021 Junyeong Jeong <rhdxmr@gmail.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use goblin::elf::sym::{st_bind, st_type, STB_GLOBAL, STT_OBJECT};
use goblin::elf::{Elf, SectionHeader};
use std::collections::HashMap as RSHashMap;
use std::ffi::{CStr, CString};
use std::fmt;
use std::io;
use std::mem;
use std::os::unix::io::{AsRawFd, RawFd};
use std::ptr;
use tracing::{debug, error, warn};

use bpf_sys::{
    btf_array, btf_enum, btf_header, btf_member, btf_param, btf_type, btf_var, btf_var_secinfo,
    BTF_INT_BOOL, BTF_INT_CHAR, BTF_INT_SIGNED, BTF_MAGIC, BTF_VAR_STATIC,
};

use crate::error::{Error, Result};

const BTF_SECTION_NAME: &str = ".BTF";

pub(crate) struct BTF {
    fd: RawFd,
    types: Vec<(u32, BtfType)>,
}

struct BtfTypeCommon {
    type_: btf_type,
    #[allow(unused)]
    name_fixed: Option<String>,
    name_raw: String,
}

enum BtfType {
    Integer(BtfTypeCommon, u32),
    Pointer(BtfTypeCommon),
    Array(BtfTypeCommon, btf_array),
    Structure(BtfTypeCommon, Vec<BtfMember>),
    Union(BtfTypeCommon, Vec<BtfMember>),
    Enumeration(BtfTypeCommon, Vec<btf_enum>),
    Forward(BtfTypeCommon),
    TypeDef(BtfTypeCommon),
    Volatile(BtfTypeCommon),
    Constant(BtfTypeCommon),
    Restrict(BtfTypeCommon),
    Function(BtfTypeCommon),
    FunctionProtocol(BtfTypeCommon, Vec<btf_param>),
    Variable(BtfTypeCommon, btf_var),
    DataSection(BtfTypeCommon, Vec<btf_var_secinfo>),
    FloatingPoint(BtfTypeCommon),
}

struct BtfMember {
    member: btf_member,
    name: String,
}

/// A structure representing BTF of a map
///
/// `btf_fd` is a file descriptor of successfully loaded BTF
///
/// `key_type_id` is a BPF type id of a key of a map
///
/// `value_type_id` is a BPF type id of a value of a map
#[derive(Debug)]
pub(crate) struct MapBtfTypeId {
    pub(crate) btf_fd: RawFd,
    pub(crate) key_type_id: u32,
    pub(crate) value_type_id: u32,
}

impl BTF {
    /// Parse .BTF section
    ///
    /// `object` is `Elf` representing whole ELF relocatable file.
    ///
    /// `bytes` is binary data of whole ELF relocatable file.
    pub(crate) fn parse(object: &Elf, bytes: &[u8]) -> Result<BTF> {
        let mut btf_bytes = get_section_header_by_name(object, BTF_SECTION_NAME)
            .map(|shdr| {
                let mut v = vec![0u8; shdr.sh_size as usize];
                v.as_mut_slice().copy_from_slice(
                    &bytes[shdr.sh_offset as usize..(shdr.sh_offset + shdr.sh_size) as usize],
                );
                v.into_boxed_slice()
            })
            .ok_or_else(|| Error::Section("BTF section not found".to_string()))?;
        if mem::size_of::<btf_header>() > btf_bytes.len() {
            return Err(Error::BTF("BTF section data size is too small".to_string()));
        }
        let btf_hdr = unsafe { ptr::read_unaligned::<btf_header>(btf_bytes.as_ptr() as *const _) };
        if btf_hdr.magic != BTF_MAGIC as u16 {
            return Err(Error::BTF(
                "illegal magic. not a valid BTF section".to_string(),
            ));
        }
        if btf_hdr.version != 1 {
            return Err(Error::BTF(format!(
                "unsupported BTF version: {}",
                btf_hdr.version
            )));
        }
        if (btf_hdr.hdr_len + btf_hdr.str_off + btf_hdr.str_len) as usize != btf_bytes.len() {
            return Err(Error::BTF("invalid binary data length".to_string()));
        }

        // Vec<(data ptr, BtfType, type id)>
        let mut btf_types = Self::parse_types(&btf_hdr, &mut btf_bytes)?;

        Self::fix_datasection(&mut btf_types, object)?;
        for (_, type_, type_id) in btf_types.iter() {
            debug!("[{}] {:?}", type_id, type_);
        }

        let mut v = vec![0i8; 64 * 1024];
        let log_buf = v.as_mut_ptr();
        let log_buf_size = v.capacity() * mem::size_of_val(&v[0]);
        let fd;
        unsafe {
            fd = bpf_sys::bpf_load_btf(
                btf_bytes.as_ptr() as *const _,
                btf_bytes.len() as u32,
                log_buf,
                log_buf_size as u32,
                false,
            );
            if fd < 0 {
                let cstr = CStr::from_ptr(log_buf);
                error!("error on bpf_load_btf: {}", cstr.to_str().unwrap());
                return Err(Error::IO(io::Error::last_os_error()));
            }
        }
        Ok(BTF {
            fd,
            types: btf_types
                .into_iter()
                .map(|(_, type_, type_id)| (type_id, type_))
                .collect(),
        })
    }

    /// Helper function for fixing BPF datasection type
    ///
    /// the value of `size` field of a BPF datasection type is always zero at
    /// compile time. so it is required to correct the value at runtime
    fn fix_datasection(btf_types: &mut Vec<(*mut u8, BtfType, u32)>, object: &Elf) -> Result<()> {
        // fix size of datasection
        let mut var_type_ids = vec![];
        for (data, type_, _) in btf_types.iter_mut() {
            if let BtfType::DataSection(comm, vsis) = type_ {
                let shdr = get_section_header_by_name(object, &comm.name_raw).ok_or_else(|| {
                    Error::Section(format!("DataSection not found: {}", &comm.name_raw))
                })?;
                comm.set_size(shdr.sh_size as u32);
                var_type_ids.extend(vsis.iter().map(|vsi| vsi.type_));
                type_.dump(*data)?;
            }
        }
        // fix offset of var section info
        let mut var_offsets = RSHashMap::new();
        for vti in var_type_ids {
            let var = btf_types
                .iter()
                .find_map(|(_, type_, type_id)| {
                    if let BtfType::Variable(..) = type_ {
                        if &vti == type_id {
                            return Some(type_);
                        }
                    }
                    None
                })
                .ok_or_else(|| Error::BTF(format!("Variable with type_id={} not found", vti)))?;

            if let BtfType::Variable(common, v) = var {
                if v.linkage == BTF_VAR_STATIC {
                    continue;
                }

                let sym = object
                    .syms
                    .iter()
                    .find(|sym| {
                        if !(st_bind(sym.st_info) == STB_GLOBAL
                            && st_type(sym.st_info) == STT_OBJECT)
                        {
                            return false;
                        }
                        if let Some(sym_name) = object.strtab.get_at(sym.st_name) {
                            if sym_name == &common.name_raw {
                                return true;
                            }
                        }
                        false
                    })
                    .ok_or_else(|| {
                        Error::BTF(format!("offset not found. BTF variable type_id={}", vti))
                    })?;
                var_offsets.insert(vti, sym.st_value);
            }
        }
        for (data, type_, _) in btf_types.iter_mut() {
            if let BtfType::DataSection(_, vsis) = type_ {
                let mut modified = false;
                for vsi in vsis.iter_mut() {
                    // offsets of variables whose linkage is static are intact
                    if let Some(offset) = var_offsets.get(&vsi.type_) {
                        vsi.offset = *offset as u32;
                        modified = true;
                    }
                }
                if modified {
                    type_.dump(*data)?;
                }
            }
        }
        Ok(())
    }

    /// Helper function for parsing BPF type encoding binary data.
    fn parse_types(
        btf_hdr: &btf_header,
        btf_bytes: &mut [u8],
    ) -> Result<Vec<(*mut u8, BtfType, u32)>> {
        let mut btf_types = vec![];
        let type_start = unsafe {
            btf_bytes
                .as_ptr()
                .offset((btf_hdr.hdr_len + btf_hdr.type_off) as isize)
        };
        let type_end = unsafe { type_start.offset(btf_hdr.type_len as isize) };
        let mut type_ptr = type_start;
        // type id 0 is reserved for void type. so type id is starting from 1.
        let mut type_id: u32 = 1;
        let str_bytes = &mut btf_bytes[(btf_hdr.hdr_len + btf_hdr.str_off) as usize..];
        while type_ptr < type_end {
            let type_ = BtfType::parse(type_ptr as *mut _, str_bytes)?;
            let sz = type_.byte_len();
            btf_types.push((type_ptr as *mut _, type_, type_id));
            type_ptr = unsafe { type_ptr.offset(sz as isize) };
            type_id += 1;
        }
        Ok(btf_types)
    }

    fn get_type_by_id(&self, type_id: u32) -> Option<&BtfType> {
        self.types
            .iter()
            .find_map(|(tid, type_)| if &type_id == tid { Some(type_) } else { None })
    }

    /// Get BTF type ids of a map which is defined at `section_name` section
    ///
    /// `section_name` indicates a section of an ELF relocatable file. Normally
    /// the name starts with `maps/`.
    pub(crate) fn get_map_type_ids(&self, section_name: &str) -> Option<MapBtfTypeId> {
        use BtfType::*;
        let vsis = self.types.iter().find_map(|(_type_id, type_)| {
            if let DataSection(common, vsis) = type_ {
                if &common.name_raw == section_name {
                    return Some(vsis);
                }
            }
            None
        })?;
        vsis.iter().find_map(|vsi| {
            if let var @ Variable(..) = self.get_type_by_id(vsi.type_)? {
                if let Structure(struct_comm, members) = self.get_type_by_id(var.type_id()?)? {
                    if &struct_comm.name_raw == "MapBtf" {
                        let key_type_id = members.iter().find_map(|memb| {
                            if &memb.name == "key_type" {
                                Some(memb.member.type_)
                            } else {
                                None
                            }
                        })?;
                        let value_type_id = members.iter().find_map(|memb| {
                            if &memb.name == "value_type" {
                                Some(memb.member.type_)
                            } else {
                                None
                            }
                        })?;
                        return Some(MapBtfTypeId {
                            btf_fd: self.as_raw_fd(),
                            key_type_id,
                            value_type_id,
                        });
                    }
                }
            }
            None
        })
    }
}

impl Drop for BTF {
    fn drop(&mut self) {
        unsafe {
            let _ = libc::close(self.fd);
        }
    }
}

impl AsRawFd for BTF {
    #[inline]
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl BtfTypeCommon {
    fn parse(bytes: *const u8, str_bytes: &[u8]) -> Result<Self> {
        let type_ = unsafe { ptr::read_unaligned(bytes as *const btf_type) };
        let name = get_type_name(str_bytes, type_.name_off)?;
        Ok(Self {
            type_,
            name_fixed: None,
            name_raw: name,
        })
    }

    fn kind(&self) -> u32 {
        (self.type_.info >> 24) & 0x0f
    }

    fn vlen(&self) -> u32 {
        self.type_.info & 0xffff
    }

    fn kind_flag(&self) -> bool {
        self.type_.info >> 31 == 1
    }

    fn size(&self) -> u32 {
        unsafe { self.type_.__bindgen_anon_1.size }
    }

    fn set_size(&mut self, sz: u32) {
        self.type_.__bindgen_anon_1.size = sz;
    }

    fn type_id(&self) -> u32 {
        unsafe { self.type_.__bindgen_anon_1.type_ }
    }
}

impl BtfType {
    fn parse(bytes: *mut u8, str_bytes: &mut [u8]) -> Result<Self> {
        let comm = BtfTypeCommon::parse(bytes, str_bytes)?;
        let vlen = comm.vlen();
        use BtfType::*;
        let mut type_ = match comm.kind() {
            1 => Integer(comm, Self::read_extra::<u32>(bytes)),
            2 => Pointer(comm),
            3 => Array(comm, Self::read_extra::<btf_array>(bytes)),
            4 => Structure(comm, {
                Self::read_multiple_extra::<btf_member>(bytes, vlen)
                    .into_iter()
                    .map(|memb| BtfMember {
                        member: memb,
                        name: get_type_name(str_bytes, memb.name_off).unwrap_or_else(|_| {
                            warn!("failed to get type name of a member");
                            "".to_string()
                        }),
                    })
                    .collect()
            }),
            5 => Union(comm, {
                Self::read_multiple_extra::<btf_member>(bytes, vlen)
                    .into_iter()
                    .map(|memb| BtfMember {
                        member: memb,
                        name: get_type_name(str_bytes, memb.name_off).unwrap_or_else(|_| {
                            warn!("failed to get type name of a member");
                            "".to_string()
                        }),
                    })
                    .collect()
            }),
            6 => Enumeration(comm, Self::read_multiple_extra::<btf_enum>(bytes, vlen)),
            7 => Forward(comm),
            8 => TypeDef(comm),
            9 => Volatile(comm),
            10 => Constant(comm),
            11 => Restrict(comm),
            12 => Function(comm),
            13 => FunctionProtocol(comm, Self::read_multiple_extra::<btf_param>(bytes, vlen)),
            14 => Variable(comm, Self::read_extra::<btf_var>(bytes)),
            15 => DataSection(
                comm,
                Self::read_multiple_extra::<btf_var_secinfo>(bytes, vlen),
            ),
            16 => FloatingPoint(comm),
            _ => {
                // it can happen normally because new BPF type can be
                // introduced to linux kernel while redBPF does not support it
                // yet.
                // But we can not keep progressing from this point because the
                // unknown type may have following data in addition to btf_type
                // struct but we can not get to know of it.
                error!("Unknown BTF type: {}", comm.kind());
                return Err(Error::BTF(format!("Unknown BTF type: {}", comm.kind())));
            }
        };

        // fix btf type name
        let typestr = type_.type_str();
        match &mut type_ {
            TypeDef(comm) | Forward(comm) | Function(comm) => {
                if comm.type_.name_off == 0 {
                    let msg = format!("{} must have a name", typestr);
                    error!("{}", msg);
                    return Err(Error::BTF(msg));
                }
                let name_fixed = fix_btf_identifier(comm.name_raw.as_str());
                if name_fixed != comm.name_raw {
                    debug!("`{}' is an invalid name. invalid characters are substituted with underscores", comm.name_raw);
                    Self::fix_name_str_section(name_fixed.as_str(), &comm.type_, str_bytes);
                }
                comm.name_fixed = Some(name_fixed);
            }
            Variable(comm, _) | DataSection(comm, _) => {
                if comm.type_.name_off == 0 {
                    let msg = format!("{} must have a name", typestr);
                    error!("{}", msg);
                    return Err(Error::BTF(msg));
                }
                let name_fixed = fix_btf_name(comm.name_raw.as_str());
                if name_fixed != comm.name_raw {
                    debug!("`{}' is an invalid name. invalid characters are substituted with underscores", comm.name_raw);
                    Self::fix_name_str_section(name_fixed.as_str(), &comm.type_, str_bytes);
                }
                comm.name_fixed = Some(name_fixed);
            }
            Pointer(comm)
            | Volatile(comm)
            | Constant(comm)
            | Restrict(comm)
            | Array(comm, _)
            | FunctionProtocol(comm, _) => {
                if comm.type_.name_off != 0 {
                    debug!(
                        "`{}' type should not have a name but its name is `{}'. erase the name",
                        typestr, comm.name_raw
                    );
                    comm.name_fixed = None;
                    comm.type_.name_off = 0;
                    type_.dump(bytes)?;
                }
            }
            Structure(comm, _)
            | Union(comm, _)
            | Enumeration(comm, _)
            | Integer(comm, _)
            | FloatingPoint(comm) => {
                if comm.type_.name_off != 0 {
                    let name_fixed = fix_btf_identifier(comm.name_raw.as_str());
                    if comm.name_raw != name_fixed {
                        debug!("`{}' is an invalid name. invalid characters are substituted with underscores", comm.name_raw);
                        Self::fix_name_str_section(name_fixed.as_str(), &comm.type_, str_bytes);
                    }
                    comm.name_fixed = Some(name_fixed);
                }
            }
        }
        Ok(type_)
    }

    fn type_str(&self) -> String {
        use BtfType::*;
        match self {
            Integer(..) => "Integer",
            Pointer(..) => "Pointer",
            Array(..) => "Array",
            Structure(..) => "Structure",
            Union(..) => "Union",
            Enumeration(..) => "Enumeration",
            Forward(..) => "Forward",
            TypeDef(..) => "TypeDef",
            Volatile(..) => "Volatile",
            Constant(..) => "Constant",
            Restrict(..) => "Restrict",
            Function(..) => "Function",
            FunctionProtocol(..) => "FunctionProtocol",
            Variable(..) => "Variable",
            DataSection(..) => "DataSection",
            FloatingPoint(..) => "FloatingPoint",
        }
        .to_string()
    }

    /// size of binary including `btf_type` structure and extra data.
    fn byte_len(&self) -> usize {
        use BtfType::*;
        mem::size_of::<btf_type>()
            + match self {
                Pointer(_) | Forward(_) | TypeDef(_) | Volatile(_) | Constant(_) | Restrict(_)
                | Function(_) | FloatingPoint(_) => 0,
                Integer(..) => mem::size_of::<u32>(),
                Array(..) => mem::size_of::<btf_array>(),
                Variable(..) => mem::size_of::<btf_var>(),
                Structure(..) => self.vlen().unwrap() as usize * mem::size_of::<btf_member>(),
                Union(..) => self.vlen().unwrap() as usize * mem::size_of::<btf_member>(),
                Enumeration(..) => self.vlen().unwrap() as usize * mem::size_of::<btf_enum>(),
                FunctionProtocol(..) => self.vlen().unwrap() as usize * mem::size_of::<btf_param>(),
                DataSection(..) => {
                    self.vlen().unwrap() as usize * mem::size_of::<btf_var_secinfo>()
                }
            }
    }

    fn vlen(&self) -> Option<u32> {
        use BtfType::*;
        match self {
            Structure(comm, ..)
            | Union(comm, ..)
            | Enumeration(comm, ..)
            | FunctionProtocol(comm, ..)
            | DataSection(comm, ..) => Some(comm.vlen()),
            Integer(..) | Pointer(_) | Array(..) | Forward(_) | TypeDef(_) | Volatile(_)
            | Constant(_) | Restrict(_) | Function(_) | Variable(..) | FloatingPoint(_) => None,
        }
    }

    fn size(&self) -> Option<u32> {
        use BtfType::*;
        match self {
            Integer(comm, ..)
            | Enumeration(comm, ..)
            | Structure(comm, ..)
            | Union(comm, ..)
            | DataSection(comm, ..)
            | FloatingPoint(comm) => Some(comm.size()),
            Pointer(..) | TypeDef(..) | Volatile(..) | Constant(..) | Restrict(..)
            | Function(..) | FunctionProtocol(..) | Variable(..) | Array(..) | Forward(..) => None,
        }
    }

    fn type_id(&self) -> Option<u32> {
        use BtfType::*;
        match self {
            Pointer(comm)
            | TypeDef(comm)
            | Volatile(comm)
            | Constant(comm)
            | Restrict(comm)
            | Function(comm)
            | FunctionProtocol(comm, ..)
            | Variable(comm, ..)
            | Forward(comm) => Some(comm.type_id()),
            Integer(..) | Enumeration(..) | Structure(..) | Union(..) | DataSection(..)
            | Array(..) | FloatingPoint(_) => None,
        }
    }

    fn dump(&self, out: *mut u8) -> Result<()> {
        use BtfType::*;
        match self {
            DataSection(comm, vsis) => unsafe {
                let mut dst = out;
                ptr::write_unaligned(dst as *mut btf_type, comm.type_);
                dst = dst.offset(mem::size_of::<btf_type>() as isize);
                for vsi in vsis.iter() {
                    ptr::write_unaligned(dst as *mut btf_var_secinfo, *vsi);
                    dst = dst.offset(mem::size_of::<btf_var_secinfo>() as isize);
                }
                Ok(())
            },
            Pointer(comm) | Volatile(comm) | Constant(comm) | Restrict(comm) => unsafe {
                ptr::write_unaligned(out as *mut btf_type, comm.type_);
                Ok(())
            },
            Array(comm, arr) => unsafe {
                ptr::write_unaligned(out as *mut btf_type, comm.type_);
                ptr::write_unaligned(
                    out.offset(mem::size_of::<btf_array>() as isize) as *mut btf_array,
                    *arr,
                );
                Ok(())
            },
            FunctionProtocol(comm, params) => unsafe {
                let mut dst = out;
                ptr::write_unaligned(dst as *mut btf_type, comm.type_);
                dst = dst.offset(mem::size_of::<btf_type>() as isize);
                for param in params.iter() {
                    ptr::write_unaligned(dst as *mut btf_param, *param);
                    dst = dst.offset(mem::size_of::<btf_param>() as isize);
                }
                Ok(())
            },
            _ => Err(Error::BTF(format!("dump is not supported for {:?}", self))),
        }
    }

    /// overwrite fixed name binary into string section
    fn fix_name_str_section(name_fixed: &str, type_: &btf_type, str_bytes: &mut [u8]) {
        let cname = CString::new(name_fixed.to_string()).unwrap();
        let cname_bytes = cname.as_bytes();
        str_bytes[type_.name_off as usize..type_.name_off as usize + cname_bytes.len()]
            .copy_from_slice(cname_bytes);
    }

    /// `data` is a pointer to binary data of `btf_type`
    fn read_multiple_extra<T>(data: *const u8, vlen: u32) -> Vec<T> {
        let head_ptr = unsafe { data.offset(mem::size_of::<btf_type>() as isize) as *const T };
        (0..vlen)
            .map(|i| unsafe { ptr::read_unaligned(head_ptr.offset(i as isize)) })
            .collect()
    }

    /// `data` is a pointer to binary data of `btf_type`
    fn read_extra<T>(data: *const u8) -> T {
        unsafe { ptr::read_unaligned(data.offset(mem::size_of::<btf_type>() as isize) as *const T) }
    }
}

impl fmt::Debug for BtfType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let anon = "(anon)".to_string();
        let fmt_type_kind = |f: &mut fmt::Formatter<'_>, t: &BtfTypeCommon| {
            write!(
                f,
                "{} '{}' type_id={}",
                (&self).type_str(),
                if t.name_raw.is_empty() {
                    &anon
                } else {
                    &t.name_raw
                },
                self.type_id().unwrap()
            )
        };

        use BtfType::*;
        match self {
            Integer(comm, u) => {
                let mut enc_v = vec![];
                let enc = btf_int_encoding(*u);
                if enc & BTF_INT_SIGNED == 1 {
                    enc_v.push("SIGNED");
                }
                if enc & BTF_INT_CHAR == 1 {
                    enc_v.push("CHAR");
                }
                if enc & BTF_INT_BOOL == 1 {
                    enc_v.push("BOOL");
                }
                let enc_str = if enc_v.is_empty() {
                    "(none)".to_string()
                } else {
                    enc_v.join(" ")
                };
                write!(
                    f,
                    "Integer '{}' size={} encoding={} bits_offset={} nr_bits={}",
                    if comm.name_raw.is_empty() {
                        &anon
                    } else {
                        &comm.name_raw
                    },
                    self.size().unwrap(),
                    enc_str,
                    btf_int_offset(*u),
                    btf_int_bits(*u)
                )
            }
            Array(comm, a) => write!(
                f,
                "Array '{}' type_id={} index_type_id={} nr_elems={}",
                if comm.name_raw.is_empty() {
                    &anon
                } else {
                    &comm.name_raw
                },
                a.type_,
                a.index_type,
                a.nelems
            ),
            Structure(comm, btf_membs) | Union(comm, btf_membs) => {
                write!(
                    f,
                    "{} '{}' size={} vlen={}",
                    self.type_str(),
                    if comm.name_raw.is_empty() {
                        &anon
                    } else {
                        &comm.name_raw
                    },
                    self.size().unwrap(),
                    self.vlen().unwrap(),
                )?;

                for bm in btf_membs.iter() {
                    write!(
                        f,
                        "\n\t'{}' type_id={} bits_offset={}",
                        bm.name, bm.member.type_, bm.member.offset
                    )?;
                }

                write!(f, "")
            }
            Enumeration(comm, ..) => write!(
                f,
                "Enumeration '{}' size={} vlen={}",
                if comm.name_raw.is_empty() {
                    &anon
                } else {
                    &comm.name_raw
                },
                self.size().unwrap(),
                self.vlen().unwrap(),
            ),
            Forward(comm) => {
                let fwd_kind = if comm.kind_flag() {
                    "Structure"
                } else {
                    "Union"
                };
                write!(
                    f,
                    "Forward '{}' fwd_kind={}",
                    if comm.name_raw.is_empty() {
                        &anon
                    } else {
                        &comm.name_raw
                    },
                    fwd_kind
                )
            }
            Pointer(comm)
            | TypeDef(comm, ..)
            | Volatile(comm, ..)
            | Constant(comm, ..)
            | Restrict(comm, ..)
            | Function(comm, ..)
            | Variable(comm, ..) => fmt_type_kind(f, comm),
            FunctionProtocol(comm, ..) => {
                write!(
                    f,
                    "FunctionProtocol '{}' type_id={} vlen={}",
                    if comm.name_raw.is_empty() {
                        &anon
                    } else {
                        &comm.name_raw
                    },
                    self.type_id().unwrap(),
                    self.vlen().unwrap(),
                )
            }
            DataSection(comm, vsis) => {
                write!(
                    f,
                    "DataSection '{}' size={} vlen={}",
                    if comm.name_raw.is_empty() {
                        &anon
                    } else {
                        &comm.name_raw
                    },
                    self.size().unwrap(),
                    self.vlen().unwrap(),
                )?;
                for vsi in vsis.iter() {
                    write!(
                        f,
                        "\n\ttype_id={} offset={} size={}",
                        vsi.type_, vsi.offset, vsi.size
                    )?;
                }
                write!(f, "")
            }
            FloatingPoint(comm) => {
                write!(
                    f,
                    "FloatingPoint '{}' size={}",
                    if comm.name_raw.is_empty() {
                        &anon
                    } else {
                        &comm.name_raw
                    },
                    self.size().unwrap(),
                )
            }
        }
    }
}

fn fix_btf_identifier(btf_id: &str) -> String {
    btf_id
        .chars()
        .enumerate()
        .map(|(i, c)| match c {
            '0'..='9' if i == 0 => '_',
            '_' | 'A'..='Z' | 'a'..='z' | '0'..='9' => c,
            _ => '_',
        })
        .collect()
}

fn fix_btf_name(btf_name: &str) -> String {
    btf_name
        .chars()
        .enumerate()
        .map(|(i, c)| match c {
            '0'..='9' if i == 0 => '_',
            '_' | 'A'..='Z' | 'a'..='z' | '0'..='9' | '.' => c,
            _ => '_',
        })
        .collect()
}

fn btf_int_encoding(val: u32) -> u32 {
    (val & 0x0f000000) >> 24
}

fn btf_int_offset(val: u32) -> u32 {
    (val & 0x00ff0000) >> 16
}

fn btf_int_bits(val: u32) -> u32 {
    val & 0x000000ff
}

fn get_section_name<'o>(object: &'o Elf, shdr: &SectionHeader) -> Option<&'o str> {
    object.shdr_strtab.get_unsafe(shdr.sh_name)
}

fn get_section_header_by_name<'o>(object: &'o Elf, name: &str) -> Option<&'o SectionHeader> {
    object.section_headers.iter().find(|shdr| {
        if let Some(n) = get_section_name(object, shdr) {
            if n == name {
                return true;
            }
        }
        return false;
    })
}

fn get_type_name(str_bytes: &[u8], name_off: u32) -> Result<String> {
    if name_off as usize >= str_bytes.len() {
        return Err(Error::BTF("name offset is out of string data".to_string()));
    }
    Ok(unsafe {
        CStr::from_ptr(str_bytes.as_ptr().offset(name_off as isize) as *const i8)
            .to_string_lossy()
            .into_owned()
    })
}
