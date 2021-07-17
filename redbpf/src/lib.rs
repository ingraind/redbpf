// Copyright 2019 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
/*!
Rust API to load BPF programs.

# Overview

The redbpf crate provides an idiomatic Rust API to load and interact with BPF
programs. It is part of the larger [redbpf
project](https://github.com/foniod/redbpf).

BPF programs used with `redbpf` are typically created and built with
[`cargo-bpf`](../../cargo_bpf/), and use the
[`redbpf-probes`](../../redbpf_probes/) and
[`redbpf-macros`](../../redbpf_macros/) APIs.

For full featured examples on how to use redbpf see
<https://github.com/foniod/redbpf/tree/master/redbpf-tools>.

# Example

The following example loads all the `kprobes` defined in the file `iotop.elf`.

```no_run
use redbpf::load::Loader;

let mut loader = Loader::load_file("iotop.elf").expect("error loading probe");

// attach all the kprobes defined in iotop.elf
for kprobe in loader.kprobes_mut() {
    kprobe
        .attach_kprobe(&kprobe.name(), 0)
        .expect(&format!("error attaching program {}", kprobe.name()));
}
```
*/
#![deny(clippy::all)]
#![allow(non_upper_case_globals)]

#[macro_use]
extern crate lazy_static;

mod btf;
pub mod cpus;
mod error;
#[cfg(feature = "load")]
pub mod load;
mod perf;
mod symbols;
pub mod sys;
pub mod xdp;

pub use bpf_sys::uname;
use bpf_sys::{
    bpf_attach_type_BPF_SK_SKB_STREAM_PARSER, bpf_attach_type_BPF_SK_SKB_STREAM_VERDICT,
    bpf_create_map_attr, bpf_create_map_xattr, bpf_insn, bpf_map_def, bpf_map_info,
    bpf_map_type_BPF_MAP_TYPE_ARRAY, bpf_map_type_BPF_MAP_TYPE_PERCPU_ARRAY, bpf_prog_type,
    BPF_ANY,
};
use goblin::elf::{reloc::RelocSection, section_header as hdr, Elf, SectionHeader, Sym};

use libc::{self, pid_t};
use std::collections::HashMap as RSHashMap;
use std::ffi::{CStr, CString};
use std::fs;
use std::io::{self, ErrorKind};
use std::marker::PhantomData;
use std::mem::{self, MaybeUninit};
use std::ops::{Deref, DerefMut};
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};
use std::ptr;

use crate::btf::{MapBtfTypeId, BTF};
pub use crate::error::{Error, Result};
pub use crate::perf::*;
use crate::symbols::*;
use crate::uname::get_kernel_internal_version;

use tracing::{debug, error};

#[cfg(target_arch = "aarch64")]
pub type DataPtr = *const u8;
#[cfg(target_arch = "aarch64")]
pub type MutDataPtr = *mut u8;

#[cfg(target_arch = "x86_64")]
pub type DataPtr = *const i8;
#[cfg(target_arch = "x86_64")]
pub type MutDataPtr = *mut i8;

pub struct Module {
    pub programs: Vec<Program>,
    pub maps: Vec<Map>,
    pub license: String,
    pub version: u32,
}

/// A builder of [Module](struct.Module.html)
///
/// In most cases
/// [`redbpf::load::Loader::load`](./load/struct.Loader.html#method.load) or
/// [`redbpf::Module::parse`](struct.Module.html#method.parse) is enough to
/// achieve your goal. These functions parse maps and programs from the ELF
/// relocatable file and then load them into kernel directly. But sometimes you
/// need to manipulate the maps or the programs before load them. That's why
/// `ModuleBuilder` exists.
///
/// By `ModuleBuilder` you can achieve one goal at this moment: sharing maps
/// among multiple independent BPF programs and their corresponding userspace
/// programs by calling
/// [`ModuleBuilder::replace_map`](struct.ModuleBuilder.html#method.replace_map)
///
/// cf. Here, "independent BPF programs" means that each BPF program had been
/// compiled into a different ELF relocatable file. You don't have to deal with
/// `ModuleBuilder` if all BPF programs are compiled into one ELF relocatable
/// file.
pub struct ModuleBuilder<'a> {
    object: Elf<'a>,
    programs: RSHashMap<usize, Program>,
    map_builders: RSHashMap<usize, MapBuilder<'a>>,
    symval_to_map_builders: RSHashMap<u64, MapBuilder<'a>>,
    rels: Vec<RelocationInfo>,
    license: String,
    version: u32,
    // BTF should survive until all maps are created with it. So keep it
    #[allow(dead_code)]
    btf: Option<BTF>,
}

enum ProbeAttachType {
    Entry,
    Return,
}

/// A BPF program defined in a [Module](struct.Module.html).
pub enum Program {
    KProbe(KProbe),
    KRetProbe(KProbe),
    UProbe(UProbe),
    URetProbe(UProbe),
    SocketFilter(SocketFilter),
    TracePoint(TracePoint),
    XDP(XDP),
    StreamParser(StreamParser),
    StreamVerdict(StreamVerdict),
}

struct ProgramData {
    pub name: String,
    code: Vec<bpf_insn>,
    fd: Option<RawFd>,
}

struct KProbeAttachmentPoint {
    fn_name: String,
    offset: u64,
    pfd: RawFd, // file descriptor of perf event
}

struct UProbeAttachmentPoint {
    fn_name: Option<String>,
    offset: u64,
    target: String,
    pid: Option<pid_t>,
    pfd: RawFd, // file descriptor of perf event
}

/// Type to work with `kprobes` or `kretprobes`.
pub struct KProbe {
    common: ProgramData,
    attach_type: ProbeAttachType,
    attachment_points: Vec<KProbeAttachmentPoint>,
}

/// Type to work with `uprobes` or `uretprobes`.
pub struct UProbe {
    common: ProgramData,
    attach_type: ProbeAttachType,
    attachment_points: Vec<UProbeAttachmentPoint>,
}

/// Type to work with `socket filters`.
pub struct SocketFilter {
    common: ProgramData,
}

pub struct TracePoint {
    common: ProgramData,
}
/// Type to work with `XDP` programs.
pub struct XDP {
    common: ProgramData,
    interfaces: Vec<String>,
}

/// Type to work with `stream_parser` BPF programs.
pub struct StreamParser {
    common: ProgramData,
}

/// Type to work with `stream_verdict` BPF programs.
pub struct StreamVerdict {
    common: ProgramData,
}

#[derive(Debug)]
pub struct Map {
    pub name: String,
    pub kind: u32,
    fd: RawFd,
    config: bpf_map_def,
    section_data: bool,
    pin_file: Option<Box<Path>>,
}

enum MapBuilder<'a> {
    Normal {
        name: String,
        def: bpf_map_def,
        btf_type_id: Option<MapBtfTypeId>,
    },
    SectionData {
        name: String,
        bytes: &'a [u8],
    },
    ExistingMap(Map),
}

pub struct HashMap<'a, K: Clone, V: Clone> {
    base: &'a Map,
    _k: PhantomData<K>,
    _v: PhantomData<V>,
}

pub struct StackTrace<'a> {
    base: &'a Map,
}

/// SockMap structure for storing file descriptors of TCP sockets by userspace
/// program.
///
/// A sockmap is a BPF map type that holds references to sock structs. BPF
/// programs can use the sockmap to redirect `skb`s between sockets using
/// related BPF helpers.
///
/// The counterpart which is used by BPF program is:
/// [`redbpf_probes::maps::SockMap`](../redbpf_probes/maps/struct.SockMap.html).
pub struct SockMap<'a> {
    base: &'a Map,
}

/// Array map corresponding to BPF_MAP_TYPE_ARRAY
///
/// # Example
/// ```no_run
/// use redbpf::{load::Loader, Array};
/// let loaded = Loader::load(b"biolatpcts.elf").expect("error loading BPF program");
/// let biolat = Array::<u64>::new(loaded.map("biolat").expect("arr not found")).expect("error creating Array in userspace");
/// let v = biolat.get(0).unwrap();
/// ```
///
/// This structure is used by userspace programs. For BPF program's API, see [`redbpf_probes::maps::Array`](../redbpf_probes/maps/struct.Array.html)
pub struct Array<'a, T: Clone> {
    base: &'a Map,
    _element: PhantomData<T>,
}

/// Per-cpu array map corresponding to BPF_MAP_TYPE_PERCPU_ARRAY
///
/// # Example
/// ```no_run
/// use redbpf::{load::Loader, PerCpuArray, PerCpuValues};
/// let loaded = Loader::load(b"biolatpcts.elf").expect("error loading BPF program");
/// let biolat = PerCpuArray::<u64>::new(loaded.map("biolat").expect("arr not found")).expect("error creating Array in userspace");
/// let mut values = PerCpuValues::new(0);
/// values[0] = 1;
/// values[1] = 10;
/// biolat.set(0, &values);
/// ```
///
/// This structure is used by userspace programs. For BPF program's API, see [`redbpf_probes::maps::PerCpuArray`](../redbpf_probes/maps/struct.PerCpuArray.html)
pub struct PerCpuArray<'a, T: Clone> {
    base: &'a Map,
    _element: PhantomData<T>,
}

// TODO Use PERF_MAX_STACK_DEPTH
const BPF_MAX_STACK_DEPTH: usize = 127;

#[repr(C)]
pub struct BpfStackFrames {
    pub ip: [u64; BPF_MAX_STACK_DEPTH],
}

/// Program array map.
///
/// An array of eBPF programs that can be used as a jump table.
///
/// To use this from eBPF code, see
/// [`redbpf_probes::maps::ProgramArray`](../redbpf_probes/maps/struct.ProgramArray.html).
pub struct ProgramArray<'a> {
    base: &'a Map,
}

#[allow(dead_code)]
pub struct RelocationInfo {
    target_sec_idx: usize,
    offset: u64,
    sym_idx: usize,
}

impl Program {
    #[allow(clippy::unnecessary_wraps)]
    fn new(kind: &str, name: &str, code: &[u8]) -> Result<Program> {
        let code = zero::read_array(code).to_vec();
        let name = name.to_string();

        let common = ProgramData {
            name,
            code,
            fd: None,
        };

        Ok(match kind {
            "kprobe" => Program::KProbe(KProbe {
                common,
                attach_type: ProbeAttachType::Entry,
                attachment_points: Vec::new(),
            }),
            "kretprobe" => Program::KProbe(KProbe {
                common,
                attach_type: ProbeAttachType::Return,
                attachment_points: Vec::new(),
            }),
            "uprobe" => Program::UProbe(UProbe {
                common,
                attach_type: ProbeAttachType::Entry,
                attachment_points: Vec::new(),
            }),
            "uretprobe" => Program::UProbe(UProbe {
                common,
                attach_type: ProbeAttachType::Return,
                attachment_points: Vec::new(),
            }),
            "tracepoint" => Program::TracePoint(TracePoint { common }),
            "socketfilter" => Program::SocketFilter(SocketFilter { common }),
            "xdp" => Program::XDP(XDP {
                common,
                interfaces: Vec::new(),
            }),
            "streamparser" => Program::StreamParser(StreamParser { common }),
            "streamverdict" => Program::StreamVerdict(StreamVerdict { common }),
            _ => return Err(Error::Section(kind.to_string())),
        })
    }

    fn to_prog_type(&self) -> bpf_prog_type {
        use Program::*;

        match self {
            KProbe(_) | KRetProbe(_) | UProbe(_) | URetProbe(_) => {
                bpf_sys::bpf_prog_type_BPF_PROG_TYPE_KPROBE
            }
            XDP(_) => bpf_sys::bpf_prog_type_BPF_PROG_TYPE_XDP,
            SocketFilter(_) => bpf_sys::bpf_prog_type_BPF_PROG_TYPE_SOCKET_FILTER,
            TracePoint(_) => bpf_sys::bpf_prog_type_BPF_PROG_TYPE_TRACEPOINT,
            StreamParser(_) | StreamVerdict(_) => bpf_sys::bpf_prog_type_BPF_PROG_TYPE_SK_SKB,
        }
    }

    fn data(&self) -> &ProgramData {
        use Program::*;

        match self {
            KProbe(p) | KRetProbe(p) => &p.common,
            UProbe(p) | URetProbe(p) => &p.common,
            XDP(p) => &p.common,
            SocketFilter(p) => &p.common,
            TracePoint(p) => &p.common,
            StreamParser(p) => &p.common,
            StreamVerdict(p) => &p.common,
        }
    }

    fn data_mut(&mut self) -> &mut ProgramData {
        use Program::*;

        match self {
            KProbe(p) | KRetProbe(p) => &mut p.common,
            UProbe(p) | URetProbe(p) => &mut p.common,
            XDP(p) => &mut p.common,
            SocketFilter(p) => &mut p.common,
            TracePoint(p) => &mut p.common,
            StreamParser(p) => &mut p.common,
            StreamVerdict(p) => &mut p.common,
        }
    }

    pub fn name(&self) -> &str {
        &self.data().name
    }

    pub fn fd(&self) -> &Option<RawFd> {
        &self.data().fd
    }

    /// Load the BPF program.
    ///
    /// BPF programs need to be loaded before they can be attached. Loading will fail if the BPF verifier rejects the code.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use redbpf::Module;
    /// let mut module = Module::parse(&std::fs::read("file.elf").unwrap()).unwrap();
    /// for program in module.programs.iter_mut() {
    ///     program
    ///         .load(module.version, module.license.clone()).unwrap()
    /// }
    /// ```
    pub fn load(&mut self, kernel_version: u32, license: String) -> Result<()> {
        if self.data().fd.is_some() {
            return Err(Error::ProgramAlreadyLoaded);
        }
        // Should bind CString to local variable not to make a dangling pointer
        // with .as_ptr() method
        let cname = CString::new(self.data().name.clone())?;
        let clicense = CString::new(license)?;

        let mut attr = unsafe { mem::zeroed::<bpf_sys::bpf_load_program_attr>() };

        attr.prog_type = self.to_prog_type();
        attr.expected_attach_type = 0;
        attr.name = cname.as_ptr();
        attr.insns = self.data().code.as_ptr();
        attr.insns_cnt = self.data().code.len() as u64;
        attr.license = clicense.as_ptr();
        attr.__bindgen_anon_1.kern_version = kernel_version;
        attr.log_level = 1;

        unsafe {
            let mut buf_vec = vec![0; 64 * 1024];
            let log_buffer: MutDataPtr = buf_vec.as_mut_ptr();
            let buf_size = buf_vec.capacity() * mem::size_of_val(&*log_buffer);
            let fd = bpf_sys::bpf_load_program_xattr(&attr, log_buffer, buf_size as u64);
            if fd < 0 {
                let cstr = CStr::from_ptr(log_buffer);
                error!("error loading BPF program {}", cstr.to_str().unwrap());
                Err(Error::BPF)
            } else {
                // free should be called to prevent memory leakage
                self.data_mut().fd = Some(fd);
                Ok(())
            }
        }
    }
}

impl Drop for ProgramData {
    fn drop(&mut self) {
        if self.fd.is_some() {
            unsafe {
                let _ = libc::close(self.fd.unwrap());
            }
        }
    }
}

fn pin_bpf_obj(fd: RawFd, file: impl AsRef<Path>) -> Result<()> {
    let mut file: PathBuf = PathBuf::from(file.as_ref());
    if file.exists() {
        error!("pinned path already exists: {:?}", file);
        return Err(Error::IO(io::Error::from(ErrorKind::AlreadyExists)));
    }
    if file.is_relative() {
        file = Path::new(".").join(file);
    }
    let dir = file.parent().unwrap();
    let existing_ancestor: Option<&Path> = dir.ancestors().find(|x| x.exists());
    if existing_ancestor.is_none() {
        if file.is_absolute() {
            error!("root directory does not exist");
        } else {
            error!("current working directory does not exist");
        }
        return Err(Error::IO(io::Error::from(ErrorKind::NotFound)));
    }
    unsafe {
        let path = existing_ancestor.unwrap();
        let cpath = CString::new(path.to_str().unwrap()).unwrap();
        let mut stat = mem::zeroed::<libc::statfs>();
        if libc::statfs(cpath.as_ptr(), &mut stat as *mut _) != 0 {
            error!("error on statfs {:?}: {}", path, io::Error::last_os_error());
            return Err(Error::IO(io::Error::last_os_error()));
        }
        if stat.f_type != libc::BPF_FS_MAGIC {
            error!("not BPF FS");
            return Err(Error::IO(io::Error::from(ErrorKind::PermissionDenied)));
        }
    };
    fs::create_dir_all(dir)?;
    unsafe {
        let cpathname = CString::new(file.to_str().unwrap())?;
        if bpf_sys::bpf_obj_pin(fd, cpathname.as_ptr()) != 0 {
            error!("error on bpf_obj_pin: {}", io::Error::last_os_error());
            Err(Error::IO(io::Error::last_os_error()))
        } else {
            Ok(())
        }
    }
}

fn unpin_bpf_obj(file: impl AsRef<Path>) -> Result<()> {
    let _ = fs::remove_file(file)?;
    Ok(())
}

impl Drop for KProbeAttachmentPoint {
    fn drop(&mut self) {
        unsafe {
            let _ = perf::detach_perf_event(self.pfd);
            let _ = libc::close(self.pfd);
        }
    }
}

impl Drop for UProbeAttachmentPoint {
    fn drop(&mut self) {
        unsafe {
            let _ = perf::detach_perf_event(self.pfd);
            let _ = libc::close(self.pfd);
        }
    }
}

impl KProbe {
    /// Attach the `kprobe` or `kretprobe`.
    ///
    /// Attach the probe to the function `fn_name` inside the kernel. If `offset`
    /// is given, the probe will be attached at that byte offset inside the
    /// function.
    ///
    /// # Example
    /// ```no_run
    /// use redbpf::Module;
    /// let mut module = Module::parse(&std::fs::read("file.elf").unwrap()).unwrap();
    /// for kprobe in module.kprobes_mut() {
    ///     kprobe.attach_kprobe(&kprobe.name(), 0).unwrap();
    /// }
    /// ```
    pub fn attach_kprobe(&mut self, fn_name: &str, offset: u64) -> Result<()> {
        let fd = self.common.fd.ok_or(Error::ProgramNotLoaded)?;
        unsafe {
            let pfd = match self.attach_type {
                ProbeAttachType::Entry => perf::open_kprobe_perf_event(fn_name, offset)?,

                ProbeAttachType::Return => perf::open_kretprobe_perf_event(fn_name, offset)?,
            };
            let ret = perf::attach_perf_event(fd, pfd);
            if ret.is_ok() {
                self.attachment_points.push(KProbeAttachmentPoint {
                    fn_name: fn_name.to_owned(),
                    offset,
                    pfd,
                });
            } else {
                libc::close(pfd);
            }
            ret
        }
    }

    /// Detach the `kprobe` or `kretprobe`
    ///
    /// This method is not needed to be called manually because all attachment
    /// points are detached and closed automatically when `KProbe` is
    /// dropped. But this method provides a feature for detaching a bpf program
    /// from kprobe event selectively.
    ///
    /// # Example
    /// ```no_run
    /// use redbpf::Module;
    /// let mut module = Module::parse(&std::fs::read("file.elf").unwrap()).unwrap();
    /// for kprobe in module.kprobes_mut() {
    ///     kprobe.attach_kprobe(&kprobe.name(), 0).unwrap();
    ///     // do some stuff...
    ///     kprobe.detach_kprobe(&kprobe.name(), 0).unwrap();
    /// }
    /// ```
    pub fn detach_kprobe(&mut self, fn_name: &str, offset: u64) -> Result<()> {
        // bpf program is detached from perf event and the perf event is closed
        // by dropping KProbeAttachmentPoint
        self.attachment_points
            .retain(|ap| !(ap.fn_name == fn_name && ap.offset == offset));
        Ok(())
    }

    pub fn name(&self) -> String {
        self.common.name.to_string()
    }

    pub fn attach_type_str(&self) -> &'static str {
        match self.attach_type {
            ProbeAttachType::Entry => "Kprobe",
            ProbeAttachType::Return => "Kretprobe",
        }
    }
}

impl UProbe {
    /// Attach the `uprobe` or `uretprobe`.
    ///
    /// Attach the probe to the function `fn_name` defined in the library or
    /// binary at `path`. If an `offset` is given, the probe will be attached at
    /// that byte offset inside the function. If `fn_name` is `None`, then
    /// `offset` is treated as an absolute address.
    ///
    /// If a `pid` is passed, only the corresponding process is traced.
    ///
    /// # Example
    /// ```no_run
    /// use redbpf::Module;
    /// let mut module = Module::parse(&std::fs::read("file.elf").unwrap()).unwrap();
    /// for uprobe in module.uprobes_mut() {
    ///     uprobe.attach_uprobe(Some(&uprobe.name()), 0, "/lib/x86_64-linux-gnu/libc-2.30.so", None).unwrap();
    /// }
    /// ```
    pub fn attach_uprobe(
        &mut self,
        fn_name: Option<&str>,
        offset: u64,
        target: &str,
        pid: Option<pid_t>,
    ) -> Result<()> {
        let fd = self.common.fd.ok_or(Error::ProgramNotLoaded)?;

        let path = if let Some(pid) = pid {
            resolve_proc_maps_lib(pid, target).unwrap_or_else(|| target.to_string())
        } else {
            match (target.starts_with('/'), LD_SO_CACHE.as_ref()) {
                (false, Ok(cache)) => cache.resolve(target).unwrap_or(target).to_string(),
                _ => target.to_owned(),
            }
        };
        let sym_offset = if let Some(fn_name) = fn_name {
            let data = fs::read(&path)?;
            let parser = ElfSymbols::parse(&data)?;
            parser
                .resolve(fn_name)
                .ok_or_else(|| Error::SymbolNotFound(fn_name.to_string()))?
                .st_value
        } else {
            0
        };
        unsafe {
            let pfd = match self.attach_type {
                ProbeAttachType::Entry => {
                    perf::open_uprobe_perf_event(&path, offset + sym_offset, pid)?
                }
                ProbeAttachType::Return => {
                    perf::open_uretprobe_perf_event(&path, offset + sym_offset, pid)?
                }
            };
            let ret = perf::attach_perf_event(fd, pfd);
            if ret.is_ok() {
                self.attachment_points.push(UProbeAttachmentPoint {
                    fn_name: fn_name.map(String::from),
                    offset,
                    target: target.to_owned(),
                    pid,
                    pfd,
                });
            } else {
                libc::close(pfd);
            }
            ret
        }
    }

    /// Detach the `uprobe` or `uretprobe`
    ///
    /// This method is not needed to be called manually because all attachment
    /// points are detached and closed automatically when `UProbe` is
    /// dropped. But this method provides a feature for detaching a bpf program
    /// from uprobe event selectively.
    ///
    /// # Example
    /// ```no_run
    /// use redbpf::Module;
    /// let mut module = Module::parse(&std::fs::read("file.elf").unwrap()).unwrap();
    /// let uprobe = module.uprobe_mut("count_strlen").expect("bpf program not found");
    /// uprobe.attach_uprobe(Some(&uprobe.name()), 0, "/lib/x86_64-linux-gnu/libc-2.30.so", None).unwrap();
    /// // do some stuff...
    /// uprobe.detach_uprobe(Some(&uprobe.name()), 0, "/lib/x86_64-linux-gnu/libc-2.30.so", None);
    /// ```
    pub fn detach_uprobe(
        &mut self,
        fn_name: Option<&str>,
        offset: u64,
        target: &str,
        pid: Option<pid_t>,
    ) -> Result<()> {
        // bpf program is detached from perf event and the perf event is closed
        // by dropping UProbeAttachmentPoint
        self.attachment_points.retain(|ap| {
            !(ap.fn_name.as_deref() == fn_name
                && ap.offset == offset
                && ap.target == target
                && ap.pid == pid)
        });
        Ok(())
    }

    pub fn name(&self) -> String {
        self.common.name.to_string()
    }
}

impl TracePoint {
    pub fn attach_trace_point(&mut self, category: &str, name: &str) -> Result<()> {
        let fd = self.common.fd.ok_or(Error::ProgramNotLoaded)?;
        // TODO Check this works correctly
        unsafe {
            let pfd = perf::open_tracepoint_perf_event(category, name)?;
            perf::attach_perf_event(fd, pfd)
        }
    }

    pub fn name(&self) -> String {
        self.common.name.to_string()
    }
}

impl XDP {
    /// Attach the XDP program.
    ///
    /// Attach the XDP program to the given network interface.
    ///
    /// # Example
    /// ```no_run
    /// # use redbpf::{Module, xdp};
    /// # let mut module = Module::parse(&std::fs::read("file.elf").unwrap()).unwrap();
    /// # for uprobe in module.xdps_mut() {
    /// uprobe.attach_xdp("eth0", xdp::Flags::default()).unwrap();
    /// # }
    /// ```
    pub fn attach_xdp(&mut self, interface: &str, flags: xdp::Flags) -> Result<()> {
        let fd = self.common.fd.ok_or(Error::ProgramNotLoaded)?;
        self.interfaces.push(interface.to_string());
        if let Err(e) = unsafe { attach_xdp(interface, fd, flags as u32) } {
            if let Error::IO(oserr) = e {
                error!("error attaching xdp to interface {}: {}", interface, oserr);
            }
            Err(Error::BPF)
        } else {
            Ok(())
        }
    }

    pub fn name(&self) -> String {
        self.common.name.to_string()
    }
}

impl Drop for XDP {
    fn drop(&mut self) {
        for interface in self.interfaces.iter() {
            let _ = unsafe { attach_xdp(interface, -1, 0) };
        }
    }
}

unsafe fn open_raw_sock(name: &str) -> Result<RawFd> {
    let sock = libc::socket(
        libc::PF_PACKET,
        libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
        (libc::ETH_P_ALL as u16).to_be().into(),
    );
    if sock < 0 {
        return Err(Error::IO(io::Error::last_os_error()));
    }

    // Do not bind on empty interface names
    if name.is_empty() {
        return Ok(sock);
    }

    let mut sll = mem::zeroed::<libc::sockaddr_ll>();
    sll.sll_family = libc::AF_PACKET as u16;
    let ciface = CString::new(name).unwrap();
    sll.sll_ifindex = libc::if_nametoindex(ciface.as_ptr()) as i32;
    if sll.sll_ifindex == 0 {
        libc::close(sock);
        return Err(Error::IO(io::Error::last_os_error()));
    }

    sll.sll_protocol = (libc::ETH_P_ALL as u16).to_be() as u16;
    if libc::bind(
        sock,
        &sll as *const _ as *const _,
        mem::size_of_val(&sll) as u32,
    ) < 0
    {
        libc::close(sock);
        return Err(Error::IO(io::Error::last_os_error()));
    }

    Ok(sock)
}

unsafe fn attach_xdp(dev_name: &str, progfd: libc::c_int, flags: libc::c_uint) -> Result<()> {
    let ciface = CString::new(dev_name).unwrap();
    let ifindex = libc::if_nametoindex(ciface.as_ptr()) as i32;
    if ifindex == 0 {
        return Err(Error::IO(io::Error::last_os_error()));
    }

    if bpf_sys::bpf_set_link_xdp_fd(ifindex, progfd, flags) != 0 {
        return Err(Error::IO(io::Error::last_os_error()));
    }
    Ok(())
}

impl SocketFilter {
    /// Attach the socket filter program.
    ///
    /// Attach the socket filter program to the given network interface.
    ///
    /// # Example
    /// ```no_run
    /// use redbpf::Module;
    /// let mut module = Module::parse(&std::fs::read("file.elf").unwrap()).unwrap();
    /// for sf in module.socket_filters_mut() {
    ///     sf.attach_socket_filter("eth0").unwrap();
    /// }
    /// ```
    pub fn attach_socket_filter(&mut self, interface: &str) -> Result<RawFd> {
        let fd = self.common.fd.ok_or(Error::ProgramNotLoaded)?;
        unsafe {
            let sfd = open_raw_sock(interface)?;
            if libc::setsockopt(
                sfd,
                libc::SOL_SOCKET,
                libc::SO_ATTACH_BPF,
                &fd as *const _ as *const _,
                mem::size_of_val(&fd) as u32,
            ) < 0
            {
                libc::close(sfd);
                Err(Error::IO(io::Error::last_os_error()))
            } else {
                Ok(sfd)
            }
        }
    }

    pub fn name(&self) -> String {
        self.common.name.to_string()
    }
}

impl Module {
    pub fn parse(bytes: &[u8]) -> Result<Module> {
        ModuleBuilder::parse(bytes)?.to_module()
    }

    pub fn map(&self, name: &str) -> Option<&Map> {
        self.maps.iter().find(|m| m.name == name)
    }

    pub fn map_mut(&mut self, name: &str) -> Option<&mut Map> {
        self.maps.iter_mut().find(|m| m.name == name)
    }

    pub fn program(&self, name: &str) -> Option<&Program> {
        self.programs.iter().find(|p| p.name() == name)
    }

    pub fn program_mut(&mut self, name: &str) -> Option<&mut Program> {
        self.programs.iter_mut().find(|p| p.name() == name)
    }

    pub fn kprobes(&self) -> impl Iterator<Item = &KProbe> {
        use Program::*;
        self.programs.iter().filter_map(|prog| match prog {
            KProbe(p) | KRetProbe(p) => Some(p),
            _ => None,
        })
    }

    pub fn kprobes_mut(&mut self) -> impl Iterator<Item = &mut KProbe> {
        use Program::*;
        self.programs.iter_mut().filter_map(|prog| match prog {
            KProbe(p) | KRetProbe(p) => Some(p),
            _ => None,
        })
    }

    pub fn kprobe_mut(&mut self, name: &str) -> Option<&mut KProbe> {
        self.kprobes_mut().find(|p| p.common.name == name)
    }

    pub fn uprobes(&self) -> impl Iterator<Item = &UProbe> {
        use Program::*;
        self.programs.iter().filter_map(|prog| match prog {
            UProbe(p) | URetProbe(p) => Some(p),
            _ => None,
        })
    }

    pub fn uprobes_mut(&mut self) -> impl Iterator<Item = &mut UProbe> {
        use Program::*;
        self.programs.iter_mut().filter_map(|prog| match prog {
            UProbe(p) | URetProbe(p) => Some(p),
            _ => None,
        })
    }

    pub fn uprobe_mut(&mut self, name: &str) -> Option<&mut UProbe> {
        self.uprobes_mut().find(|p| p.common.name == name)
    }

    pub fn xdps(&self) -> impl Iterator<Item = &XDP> {
        use Program::*;
        self.programs.iter().filter_map(|prog| match prog {
            XDP(p) => Some(p),
            _ => None,
        })
    }

    pub fn xdps_mut(&mut self) -> impl Iterator<Item = &mut XDP> {
        use Program::*;
        self.programs.iter_mut().filter_map(|prog| match prog {
            XDP(p) => Some(p),
            _ => None,
        })
    }

    pub fn xdp_mut(&mut self, name: &str) -> Option<&mut XDP> {
        self.xdps_mut().find(|p| p.common.name == name)
    }

    pub fn socket_filters(&self) -> impl Iterator<Item = &SocketFilter> {
        use Program::*;
        self.programs.iter().filter_map(|prog| match prog {
            SocketFilter(p) => Some(p),
            _ => None,
        })
    }

    pub fn socket_filters_mut(&mut self) -> impl Iterator<Item = &mut SocketFilter> {
        use Program::*;
        self.programs.iter_mut().filter_map(|prog| match prog {
            SocketFilter(p) => Some(p),
            _ => None,
        })
    }

    pub fn socket_filter_mut(&mut self, name: &str) -> Option<&mut SocketFilter> {
        self.socket_filters_mut().find(|p| p.common.name == name)
    }

    pub fn trace_points(&self) -> impl Iterator<Item = &TracePoint> {
        use Program::*;
        self.programs.iter().filter_map(|prog| match prog {
            TracePoint(p) => Some(p),
            _ => None,
        })
    }

    pub fn trace_points_mut(&mut self) -> impl Iterator<Item = &mut TracePoint> {
        use Program::*;
        self.programs.iter_mut().filter_map(|prog| match prog {
            TracePoint(p) => Some(p),
            _ => None,
        })
    }

    pub fn trace_point_mut(&mut self, name: &str) -> Option<&mut TracePoint> {
        self.trace_points_mut().find(|p| p.common.name == name)
    }

    pub fn stream_parsers(&self) -> impl Iterator<Item = &StreamParser> {
        use Program::*;
        self.programs.iter().filter_map(|prog| match prog {
            StreamParser(p) => Some(p),
            _ => None,
        })
    }

    pub fn stream_parsers_mut(&mut self) -> impl Iterator<Item = &mut StreamParser> {
        use Program::*;
        self.programs.iter_mut().filter_map(|prog| match prog {
            StreamParser(p) => Some(p),
            _ => None,
        })
    }

    pub fn stream_parser_mut(&mut self, name: &str) -> Option<&mut StreamParser> {
        self.stream_parsers_mut().find(|p| p.common.name == name)
    }

    pub fn stream_verdicts(&self) -> impl Iterator<Item = &StreamVerdict> {
        use Program::*;
        self.programs.iter().filter_map(|prog| match prog {
            StreamVerdict(p) => Some(p),
            _ => None,
        })
    }

    pub fn stream_verdicts_mut(&mut self) -> impl Iterator<Item = &mut StreamVerdict> {
        use Program::*;
        self.programs.iter_mut().filter_map(|prog| match prog {
            StreamVerdict(p) => Some(p),
            _ => None,
        })
    }

    pub fn stream_verdict_mut(&mut self, name: &str) -> Option<&mut StreamVerdict> {
        self.stream_verdicts_mut().find(|p| p.common.name == name)
    }
}

impl<'a> ModuleBuilder<'a> {
    /// Parse binary data of ELF relocatable file
    ///
    /// # Example
    /// ```no_run
    /// # static ELF_BINARY: [u8; 128] = [0u8; 128];
    /// # fn probe_code() -> &'static [u8] { &ELF_BINARY }
    /// use redbpf::ModuleBuilder;
    /// let mut builder = ModuleBuilder::parse(probe_code()).expect("error on ModuleBuilder::parse");
    /// ```
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        let object = Elf::parse(bytes)?;
        let strtab = &object.strtab;
        let symtab = object.syms.to_vec();
        let shdr_relocs = &object.shdr_relocs;

        let mut rels = vec![];
        let mut programs = RSHashMap::new();
        // maps: section header index => map
        let mut map_builders = RSHashMap::new();
        // symval_to_maps: symbol value => map
        let mut symval_to_map_builders = RSHashMap::new();

        let mut license = String::new();
        let mut version = 0u32;
        // BTF is optional
        let btf = BTF::parse(&object, bytes).ok();
        for (shndx, shdr) in object.section_headers.iter().enumerate() {
            let (kind, name) = get_split_section_name(&object, &shdr, shndx)?;

            let section_type = shdr.sh_type;
            let content = data(&bytes, &shdr);
            match (section_type, kind, name) {
                (hdr::SHT_REL, _, _) => add_relocation(&mut rels, shndx, &shdr, shdr_relocs),
                (hdr::SHT_PROGBITS, Some("version"), _) => version = get_version(&content),
                (hdr::SHT_PROGBITS, Some("license"), _) => {
                    license = zero::read_str(content).to_string()
                }
                (hdr::SHT_PROGBITS, Some(name), None)
                    if name == ".bss"
                        || name.starts_with(".data")
                        || name.starts_with(".rodata") =>
                {
                    let map_builder = MapBuilder::with_section_data(name, &content)?;
                    map_builders.insert(shndx, map_builder);
                }
                (hdr::SHT_PROGBITS, Some("maps"), Some(name)) => {
                    let mut map_builder = MapBuilder::parse(name, &content)?;
                    if let Some(ref btf) = btf {
                        if let Ok(sec_name) = get_section_name(&object, shdr) {
                            if let Some(map_btf_type_id) = btf.get_map_type_ids(sec_name) {
                                debug!("Map `{}' has BTF info. {:?}", name, map_btf_type_id);
                                let _ = map_builder.set_btf(map_btf_type_id);
                            }
                        }
                    }
                    map_builders.insert(shndx, map_builder);
                }
                (hdr::SHT_PROGBITS, Some("maps"), None) => {
                    // Somehow clang direct compiled binary (in C) uses this approach to define maps.
                    // More specifically, the maps contains all map definitions (except names).
                    let maps_syms = symtab.iter().filter(|sym| sym.st_shndx == shndx);

                    for sym in maps_syms {
                        let offset = sym.st_value as usize;
                        let name = strtab.get_at(sym.st_name).ok_or(Error::ElfError)?;
                        let cur_content = &content[offset..];
                        let map_builder = MapBuilder::parse(name, cur_content)?;
                        symval_to_map_builders.insert(sym.st_value, map_builder);
                    }
                }
                (hdr::SHT_PROGBITS, Some(kind @ "kprobe"), Some(name))
                | (hdr::SHT_PROGBITS, Some(kind @ "kretprobe"), Some(name))
                | (hdr::SHT_PROGBITS, Some(kind @ "uprobe"), Some(name))
                | (hdr::SHT_PROGBITS, Some(kind @ "uretprobe"), Some(name))
                | (hdr::SHT_PROGBITS, Some(kind @ "xdp"), Some(name))
                | (hdr::SHT_PROGBITS, Some(kind @ "socketfilter"), Some(name))
                | (hdr::SHT_PROGBITS, Some(kind @ "streamparser"), Some(name))
                | (hdr::SHT_PROGBITS, Some(kind @ "streamverdict"), Some(name)) => {
                    let prog = Program::new(kind, name, &content)?;
                    programs.insert(shndx, prog);
                }
                _ => {}
            }
        }

        Ok(ModuleBuilder {
            object,
            programs,
            map_builders,
            symval_to_map_builders,
            rels,
            license,
            version,
            btf,
        })
    }

    /// Create [`Module`](struct.Module.html) from `ModuleBuilder`
    ///
    /// When this method is called, `ModuleBuilder` is moved out so the
    /// instance can not be used any more.
    ///
    /// # Example
    /// ```no_run
    /// # let arr = [0u8; 128];
    /// # let bytes = &arr;
    /// use redbpf::ModuleBuilder;
    /// let module = ModuleBuilder::parse(bytes).expect("error on ModuleBuilder::parse").to_module();
    /// ```
    pub fn to_module(mut self) -> Result<Module> {
        let symtab = self.object.syms.to_vec();
        let mut maps = RSHashMap::new();
        for (shndx, map_builder) in self.map_builders.into_iter() {
            let map = map_builder.to_map()?;
            maps.insert(shndx, map);
        }

        let mut symval_to_maps = RSHashMap::new();
        for (symval, map_builder) in self.symval_to_map_builders.into_iter() {
            let map = map_builder.to_map()?;
            symval_to_maps.insert(symval, map);
        }

        // Rewrite programs with relocation data
        for rel in self.rels.iter() {
            if self.programs.contains_key(&rel.target_sec_idx) {
                if let Err(_) = rel.apply(&mut self.programs, &maps, &symtab) {
                    // means that not normal case, we should rely on symbol value instead of section header index
                    rel.apply_with_symmap(&mut self.programs, &symval_to_maps, &symtab)?;
                }
            }
        }

        let programs = self.programs.drain().map(|(_, v)| v).collect();
        let mut maps: Vec<Map> = maps.drain().map(|(_, v)| v).collect();
        maps.extend(symval_to_maps.drain().map(|(_, v)| v));

        Ok(Module {
            programs,
            maps,
            license: self.license,
            version: self.version,
        })
    }

    /// Replace a map whose name is `map_name` with a `new` [`Map`](struct.Map.html)
    ///
    /// This method can fail if there does not exist a map whose name is
    /// `map_name` or definitions of `new` map and a map whose name is
    /// `map_name` do not match each other. The compared definition includes
    /// key size, value size, map type and the max entry number.
    ///
    /// # Example
    /// ```no_run
    /// # let arr = [0u8; 128];
    /// # let bytes = &arr;
    /// use redbpf::{ModuleBuilder, Map};
    /// let mut builder = ModuleBuilder::parse(bytes).expect("error on ModuleBuilder::parse");
    /// builder.replace_map("sharedmap", Map::from_pin_file("/sys/fs/bpf/sharedmap").expect("error on Map::from_pin_file")).expect("error on ModuleBuilder::replace_map");
    /// let mut module = builder.to_module().expect("error on ModuleBuilder::to_module");
    /// ```
    pub fn replace_map(&mut self, map_name: &str, new: Map) -> Result<&mut Self> {
        for (_, map_builder) in self.map_builders.iter_mut() {
            match map_builder {
                MapBuilder::Normal {
                    name,
                    def,
                    btf_type_id: _,
                } => {
                    if name == map_name {
                        if !(def.type_ == new.config.type_
                            && def.key_size == new.config.key_size
                            && def.value_size == new.config.value_size
                            && def.max_entries == new.config.max_entries)
                        {
                            error!("map definition does not match");
                            return Err(Error::Map);
                        }
                        *map_builder = MapBuilder::with_existing_map(new)?;
                        return Ok(self);
                    }
                }
                MapBuilder::SectionData { name, .. } => {
                    if name == map_name {
                        if !new.section_data {
                            error!("map is not for section data");
                            return Err(Error::Map);
                        }
                        *map_builder = MapBuilder::with_existing_map(new)?;
                        return Ok(self);
                    }
                }
                MapBuilder::ExistingMap(map) => {
                    if map.name == map_name {
                        if !(map.config.type_ == new.config.type_
                            && map.config.key_size == new.config.key_size
                            && map.config.value_size == new.config.value_size
                            && map.config.max_entries == new.config.max_entries)
                        {
                            error!("map definition does not match");
                            return Err(Error::Map);
                        }
                        *map_builder = MapBuilder::with_existing_map(new)?;
                        return Ok(self);
                    }
                }
            }
        }
        error!("map of which name is `{}' not found", map_name);
        Err(Error::Map)
    }
}

fn get_section_name<'o>(object: &'o Elf, shdr: &SectionHeader) -> Result<&'o str> {
    let name = object
        .shdr_strtab
        .get_unsafe(shdr.sh_name)
        .ok_or_else(|| Error::Section(format!("Section name not found")))?;
    Ok(name)
}

#[inline]
fn get_split_section_name<'o>(
    object: &'o Elf<'_>,
    shdr: &'o SectionHeader,
    shndx: usize,
) -> Result<(Option<&'o str>, Option<&'o str>)> {
    let name = get_section_name(object, shdr)
        .or_else(|_| Err(Error::Section(format!("Section name not found: {}", shndx))))?;

    let mut names = name.splitn(2, '/');

    let kind = names.next();
    let name = names.next();

    Ok((kind, name))
}

impl RelocationInfo {
    #[inline]
    pub fn apply(
        &self,
        programs: &mut RSHashMap<usize, Program>,
        maps: &RSHashMap<usize, Map>,
        symtab: &[Sym],
    ) -> Result<()> {
        // get the program we need to apply relocations to based on the program section index
        let prog = programs.get_mut(&self.target_sec_idx).ok_or(Error::Reloc)?;
        // lookup the symbol we're relocating in the symbol table
        let sym = symtab[self.sym_idx];
        // get the map referenced by the program based on the symbol section index
        let insn_idx = (self.offset / std::mem::size_of::<bpf_insn>() as u64) as usize;
        let code = &mut prog.data_mut().code;
        let map = maps.get(&sym.st_shndx).ok_or(Error::Reloc)?;

        // the index of the instruction we need to patch
        if map.section_data {
            code[insn_idx].set_src_reg(bpf_sys::BPF_PSEUDO_MAP_VALUE as u8);
            code[insn_idx + 1].imm = code[insn_idx].imm + sym.st_value as i32;
        } else {
            code[insn_idx].set_src_reg(bpf_sys::BPF_PSEUDO_MAP_FD as u8);
        }
        code[insn_idx].imm = map.fd;
        Ok(())
    }

    #[inline]
    fn apply_with_symmap(
        &self,
        programs: &mut RSHashMap<usize, Program>,
        symval_to_maps: &RSHashMap<u64, Map>,
        symtab: &[Sym],
    ) -> Result<()> {
        let prog = programs.get_mut(&self.target_sec_idx).ok_or(Error::Reloc)?;
        let sym = symtab[self.sym_idx];
        let insn_idx = (self.offset / std::mem::size_of::<bpf_insn>() as u64) as usize;
        let code = &mut prog.data_mut().code;
        let map = symval_to_maps.get(&sym.st_value).ok_or(Error::Reloc)?;
        code[insn_idx].set_src_reg(bpf_sys::BPF_PSEUDO_MAP_FD as u8);
        code[insn_idx].imm = map.fd;
        Ok(())
    }
}

impl Map {
    pub fn load(name: &str, code: &[u8]) -> Result<Map> {
        let config: bpf_map_def = *zero::read(code);
        Map::with_map_def(name, config, None)
    }

    fn with_section_data(name: &str, data: &[u8], flags: u32) -> Result<Map> {
        let mut map = Map::with_map_def(
            name,
            bpf_map_def {
                type_: bpf_sys::bpf_map_type_BPF_MAP_TYPE_ARRAY,
                key_size: mem::size_of::<u32>() as u32,
                value_size: data.len() as u32,
                max_entries: 1,
                map_flags: flags,
            },
            None,
        )?;
        map.section_data = true;
        // for BSS we don't need to copy the data, it's already 0-initialized
        if name != ".bss" {
            unsafe {
                let ret = bpf_sys::bpf_map_update_elem(
                    map.fd,
                    &mut 0 as *mut _ as *mut _,
                    data.as_ptr() as *mut u8 as *mut _,
                    0,
                );
                if ret < 0 {
                    return Err(Error::BPF);
                }
            }
        }
        Ok(map)
    }

    fn with_map_def(
        name: &str,
        config: bpf_map_def,
        btf_type_id: Option<MapBtfTypeId>,
    ) -> Result<Map> {
        let fd = unsafe {
            let cname = CString::new(name)?;
            let mut attr_uninit = MaybeUninit::<bpf_create_map_attr>::zeroed();
            let attr_ptr = attr_uninit.as_mut_ptr();
            (*attr_ptr).name = cname.as_ptr();
            (*attr_ptr).map_type = config.type_;
            (*attr_ptr).map_flags = config.map_flags;
            (*attr_ptr).key_size = config.key_size;
            (*attr_ptr).value_size = config.value_size;
            (*attr_ptr).max_entries = config.max_entries;
            if let Some(type_id) = btf_type_id {
                (*attr_ptr).btf_fd = type_id.btf_fd as u32;
                (*attr_ptr).btf_key_type_id = type_id.key_type_id;
                (*attr_ptr).btf_value_type_id = type_id.value_type_id;
            }
            let attr = attr_uninit.assume_init();
            bpf_create_map_xattr(&attr)
        };
        if fd < 0 {
            return Err(Error::Map);
        }

        Ok(Map {
            name: name.to_string(),
            kind: config.type_,
            fd,
            config,
            section_data: false,
            pin_file: None,
        })
    }

    /// Create `Map` from a file which represents pinned map
    ///
    /// # Example
    /// ```no_run
    /// use redbpf::{Array, Map};
    /// let map = Map::from_pin_file("/sys/fs/bpf/persist_map").expect("error on creating map from file");
    /// let array = Array::<u64>::new(&map).expect("error on creating array");
    /// ```
    pub fn from_pin_file(file: impl AsRef<Path>) -> Result<Map> {
        let file = file.as_ref();
        let fd = unsafe {
            let cpathname = CString::new(file.to_str().unwrap())?;
            bpf_sys::bpf_obj_get(cpathname.as_ptr())
        };
        if fd < 0 {
            error!("error on bpf_obj_get: {}", io::Error::last_os_error());
            return Err(Error::IO(io::Error::last_os_error()));
        }
        let map_info = unsafe {
            let mut info = mem::zeroed::<bpf_map_info>();
            let mut info_len = mem::size_of_val(&info) as u32;
            if bpf_sys::bpf_obj_get_info_by_fd(fd, &mut info as *mut _ as *mut _, &mut info_len)
                != 0
            {
                error!(
                    "error on bpf_obj_get_info_by_fd: {}",
                    io::Error::last_os_error()
                );
                return Err(Error::IO(io::Error::last_os_error()));
            }
            info
        };

        let name = unsafe {
            CStr::from_ptr(&map_info.name as *const _)
                .to_string_lossy()
                .into_owned()
        };
        Ok(Map {
            name,
            kind: map_info.type_,
            fd,
            config: bpf_map_def {
                type_: map_info.type_,
                key_size: map_info.key_size,
                value_size: map_info.value_size,
                max_entries: map_info.max_entries,
                map_flags: map_info.map_flags,
            },
            section_data: false,
            pin_file: Some(Box::from(file)),
        })
    }

    /// Pin map to BPF FS
    ///
    /// # Example
    /// ```no_run
    /// use redbpf::Module;
    /// use redbpf::load::Loader;
    /// let mut loaded = Loader::load_file("file.elf").expect("error loading probe");
    /// loaded.map_mut("persist_map").expect("map not found").pin("/sys/fs/bpf/persist_map").expect("error on pinning");
    /// ```
    pub fn pin(&mut self, file: impl AsRef<Path>) -> Result<()> {
        let file = file.as_ref();
        if self.pin_file.is_some() {
            error!("already pinned");
            return Err(Error::Map);
        }
        pin_bpf_obj(self.fd, file)?;
        self.pin_file = Some(Box::from(file));
        Ok(())
    }

    /// Unpin map
    ///
    /// # Example
    /// ```no_run
    /// use redbpf::Module;
    /// use redbpf::load::Loader;
    /// let mut loaded = Loader::load_file("file.elf").expect("error loading probe");
    /// let persist_map = loaded.map_mut("persist_map").expect("map not found");
    /// persist_map.pin("/sys/fs/bpf/persist_map").expect("error on pinning");
    /// // do some stuff...
    /// persist_map.unpin().expect("error on unpinning");
    /// ```
    pub fn unpin(&mut self) -> Result<()> {
        if self.pin_file.is_none() {
            error!("not pinned");
            return Err(Error::Map);
        }
        unpin_bpf_obj(self.pin_file.as_ref().unwrap())?;
        self.pin_file = None;
        Ok(())
    }
}

impl Drop for Map {
    fn drop(&mut self) {
        unsafe {
            let _ = libc::close(self.fd);
        }
    }
}

impl<'a> MapBuilder<'a> {
    fn parse(name: &str, bytes: &[u8]) -> Result<Self> {
        let def = unsafe { ptr::read_unaligned(bytes.as_ptr() as *const bpf_map_def) };
        Ok(MapBuilder::Normal {
            def,
            name: name.to_string(),
            btf_type_id: None,
        })
    }

    fn with_section_data(name: &str, bytes: &'a [u8]) -> Result<Self> {
        Ok(MapBuilder::SectionData {
            name: name.to_string(),
            bytes,
        })
    }

    fn with_existing_map(map: Map) -> Result<Self> {
        Ok(MapBuilder::ExistingMap(map))
    }

    fn set_btf(&mut self, type_id: MapBtfTypeId) -> Result<&mut Self> {
        match self {
            MapBuilder::Normal { btf_type_id, .. } => {
                *btf_type_id = Some(type_id);
                Ok(self)
            }
            MapBuilder::SectionData { .. } => {
                error!("map for section data does not support BTF");
                Err(Error::Map)
            }
            MapBuilder::ExistingMap(_) => {
                error!("can not set BTF type id to already existing map");
                Err(Error::Map)
            }
        }
    }

    fn to_map(self) -> Result<Map> {
        match self {
            MapBuilder::Normal {
                name,
                def,
                btf_type_id,
            } => Map::with_map_def(name.as_ref(), def, btf_type_id),
            MapBuilder::SectionData { name, bytes } => Map::with_section_data(
                name.as_ref(),
                bytes,
                if name.starts_with(".rodata") {
                    bpf_sys::BPF_F_RDONLY_PROG
                } else {
                    0
                },
            ),
            MapBuilder::ExistingMap(map) => Ok(map),
        }
    }
}

impl<'base, K: Clone, V: Clone> HashMap<'base, K, V> {
    pub fn new(base: &Map) -> Result<HashMap<K, V>> {
        if mem::size_of::<K>() != base.config.key_size as usize
            || mem::size_of::<V>() != base.config.value_size as usize
        {
            error!(
                "map definitions (sizes of key and value) of base `Map' and
            `HashMap' do not match"
            );
            return Err(Error::Map);
        }

        Ok(HashMap {
            base,
            _k: PhantomData,
            _v: PhantomData,
        })
    }

    pub fn set(&self, mut key: K, mut value: V) {
        unsafe {
            bpf_sys::bpf_map_update_elem(
                self.base.fd,
                &mut key as *mut _ as *mut _,
                &mut value as *mut _ as *mut _,
                0,
            );
        }
    }

    pub fn get(&self, mut key: K) -> Option<V> {
        let mut value = MaybeUninit::zeroed();
        if unsafe {
            bpf_sys::bpf_map_lookup_elem(
                self.base.fd,
                &mut key as *mut _ as *mut _,
                &mut value as *mut _ as *mut _,
            )
        } < 0
        {
            return None;
        }
        Some(unsafe { value.assume_init() })
    }

    pub fn delete(&self, mut key: K) {
        unsafe {
            bpf_sys::bpf_map_delete_elem(self.base.fd, &mut key as *mut _ as *mut _);
        }
    }

    pub fn iter<'a>(&'a self) -> MapIter<'a, '_, K, V> {
        MapIter {
            map: self,
            key: None,
        }
    }
}

impl<'base, T: Clone> Array<'base, T> {
    /// Create `Array` map from `base`
    pub fn new(base: &Map) -> Result<Array<T>> {
        if mem::size_of::<T>() != base.config.value_size as usize
            || bpf_map_type_BPF_MAP_TYPE_ARRAY != base.config.type_
        {
            error!(
                "map definitions (size of value, map type) of base `Map' and
            `Array' do not match"
            );
            return Err(Error::Map);
        }

        Ok(Array {
            base,
            _element: PhantomData,
        })
    }

    /// Set `value` into this array map at `index`
    ///
    /// This method can fail if `index` is out of bound
    pub fn set(&self, mut index: u32, mut value: T) -> Result<()> {
        let rv = unsafe {
            bpf_sys::bpf_map_update_elem(
                self.base.fd,
                &mut index as *mut _ as *mut _,
                &mut value as *mut _ as *mut _,
                0,
            )
        };
        if rv < 0 {
            Err(Error::Map)
        } else {
            Ok(())
        }
    }

    /// Get an element at `index` from this array map
    ///
    /// This method always returns a `Some(T)` if `index` is valid, but `None`
    /// can be returned if `index` is out of bound.
    pub fn get(&self, mut index: u32) -> Option<T> {
        let mut value = MaybeUninit::zeroed();
        if unsafe {
            bpf_sys::bpf_map_lookup_elem(
                self.base.fd,
                &mut index as *mut _ as *mut _,
                &mut value as *mut _ as *mut _,
            )
        } < 0
        {
            return None;
        }
        Some(unsafe { value.assume_init() })
    }

    /// Get length of this array map.
    pub fn len(&self) -> usize {
        self.base.config.max_entries as usize
    }
}

// round up to multiple of `unit_size`
//
// `unit_size` must be power of 2
fn round_up<T>(unit_size: usize) -> usize {
    let value_size = std::mem::size_of::<T>();
    ((value_size - 1) | (unit_size - 1)) + 1
}

/// A structure representing values of per-cpu map structures such as [`PerCpuArray`](./struct.PerCpuArray.html)
///
/// It is a kind of newtype of `Box<[T]>`. The length of the slice is always
/// the same with [`cpus::get_possible_num`](./cpus/fn.get_possible_num.html).
/// It also implements `Deref` and `DerefMut` so it can be used as a normal
/// array.
/// # Example
/// ```no_run
/// use redbpf::PerCpuValues;
/// let mut values = PerCpuValues::<u64>::new(0);
/// values[0] = 1;
/// ```
pub struct PerCpuValues<T: Clone>(Box<[T]>);

impl<T: Clone> PerCpuValues<T> {
    /// Create a `PerCpuValues<T>` instance
    ///
    /// The created instance contains the fixed number of elements filled with
    /// `default_value`
    pub fn new(default_value: T) -> Self {
        let count = cpus::get_possible_num();
        let v = vec![default_value; count];
        Self(v.into_boxed_slice())
    }

    // This is called by `get` methods of per-cpu map structures
    fn from_boxed_slice(v: Box<[T]>) -> Self {
        Self(v)
    }
}

impl<T: Clone> Deref for PerCpuValues<T> {
    type Target = Box<[T]>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: Clone> DerefMut for PerCpuValues<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<'base, T: Clone> PerCpuArray<'base, T> {
    pub fn new(base: &Map) -> Result<PerCpuArray<T>> {
        if mem::size_of::<T>() != base.config.value_size as usize
            || bpf_map_type_BPF_MAP_TYPE_PERCPU_ARRAY != base.config.type_
        {
            error!(
                "map definitions (size of value, map type) of base `Map' and
            `PerCpuArray' do not match"
            );
            return Err(Error::Map);
        }

        Ok(PerCpuArray {
            base,
            _element: PhantomData,
        })
    }

    /// Set per-cpu `values` to the BPF map
    ///
    /// The number of elements in `values` should be equal to the number of
    /// possible CPUs. It is guranteed if `values` is created by
    /// [`PerCpuValues::new`](./struct.PerCpuValues.html#method.new)
    ///
    /// This method can fail if `index` is out of bound of array map.
    pub fn set(&self, mut index: u32, values: &PerCpuValues<T>) -> Result<()> {
        let count = cpus::get_possible_num();
        if values.len() != count {
            return Err(Error::Map);
        }
        // It is needed to round up the value size to 8*N bytes
        // cf., https://elixir.bootlin.com/linux/v5.8/source/kernel/bpf/syscall.c#L1103
        let value_size = round_up::<T>(8);
        let alloc_size = value_size * count;
        let mut alloc = vec![0u8; alloc_size];
        let mut ptr = alloc.as_mut_ptr();
        for i in 0..count {
            unsafe {
                let dst_ptr = ptr.offset((value_size * i) as isize) as *const T as *mut T;
                ptr::write_unaligned::<T>(dst_ptr, values[i].clone());
            }
        }
        let rv = unsafe {
            bpf_sys::bpf_map_update_elem(
                self.base.fd,
                &mut index as *mut _ as *mut _,
                &mut ptr as *mut _ as *mut _,
                0,
            )
        };

        if rv < 0 {
            Err(Error::Map)
        } else {
            Ok(())
        }
    }

    /// Get per-cpu values from the BPF map
    ///
    /// Get per-cpu values at `index`. This method returns
    /// [`PerCpuValues`](./struct.PerCpuValues.html)
    ///
    /// This method can return None if `index` is out of bound.
    pub fn get(&self, mut index: u32) -> Option<PerCpuValues<T>> {
        // It is needed to round up the value size to 8*N
        // cf., https://elixir.bootlin.com/linux/v5.8/source/kernel/bpf/syscall.c#L1035
        let value_size = round_up::<T>(8);
        let count = cpus::get_possible_num();
        let alloc_size = value_size * count;
        let mut alloc = vec![0u8; alloc_size];
        let ptr = alloc.as_mut_ptr();
        if unsafe {
            bpf_sys::bpf_map_lookup_elem(
                self.base.fd,
                &mut index as *mut _ as *mut _,
                ptr as *mut _,
            )
        } < 0
        {
            return None;
        }

        let mut values = Vec::with_capacity(count);
        for i in 0..count {
            unsafe {
                let elem_ptr = ptr.offset((value_size * i) as isize) as *const T;
                values.push(ptr::read_unaligned(elem_ptr));
            }
        }

        Some(PerCpuValues::from_boxed_slice(values.into_boxed_slice()))
    }

    /// Get length of array map
    pub fn len(&self) -> usize {
        self.base.config.max_entries as usize
    }
}

impl<'base> ProgramArray<'base> {
    pub fn new(base: &Map) -> Result<ProgramArray> {
        if mem::size_of::<u32>() != base.config.key_size as usize
            || mem::size_of::<RawFd>() != base.config.value_size as usize
        {
            error!(
                "map definitions (sizes of key and value) of base `Map' and
            `ProgramArray' do not match"
            );
            return Err(Error::Map);
        }

        Ok(ProgramArray { base })
    }

    /// Get the `fd` of the eBPF program at `index`.
    pub fn get(&self, mut index: u32) -> Result<RawFd> {
        let mut fd: RawFd = 0;
        if unsafe {
            bpf_sys::bpf_map_lookup_elem(
                self.base.fd,
                &mut index as *mut _ as *mut _,
                &mut fd as *mut _ as *mut _,
            )
        } < 0
        {
            return Err(Error::Map);
        }
        Ok(fd)
    }

    /// Set the `index` entry to the given eBPF program `fd`.
    ///
    /// To jump to a program from eBPF, see
    /// [`redbpf_probes::maps::ProgramArray::tail_call`](../redbpf_probes/maps/struct.ProgramArray.html#method.tail_call).
    ///
    /// # Example
    /// ```no_run
    /// pub const PROGRAM_PARSE_HTTP: u32 = 0;
    ///
    /// use redbpf::{load::Loader, ProgramArray};
    /// let mut loader = Loader::load_file("iotop.elf").expect("error loading probe");
    /// let mut programs = ProgramArray::new(loader.map("program_map").unwrap()).unwrap();
    ///
    /// programs.set(
    ///     PROGRAM_PARSE_HTTP,
    ///     loader.program("parse_http").unwrap().fd().unwrap(),
    /// );
    /// ```
    pub fn set(&mut self, mut index: u32, mut fd: RawFd) -> Result<()> {
        let ret = unsafe {
            bpf_sys::bpf_map_update_elem(
                self.base.fd,
                &mut index as *mut _ as *mut _,
                &mut fd as *mut _ as *mut _,
                0,
            )
        };
        if ret < 0 {
            return Err(Error::Map);
        }

        Ok(())
    }
}

pub struct MapIter<'a, 'b, K: Clone, V: Clone> {
    map: &'a HashMap<'b, K, V>,
    key: Option<K>,
}

impl<K: Clone, V: Clone> Iterator for MapIter<'_, '_, K, V> {
    type Item = (K, V);

    fn next(&mut self) -> Option<Self::Item> {
        let key = self.key.take();
        self.key = match key {
            Some(mut key) => {
                let mut next_key = MaybeUninit::<K>::zeroed();
                let ret = unsafe {
                    bpf_sys::bpf_map_get_next_key(
                        self.map.base.fd,
                        &mut key as *mut _ as *mut _,
                        &mut next_key as *mut _ as *mut _,
                    )
                };
                if ret < 0 {
                    None
                } else {
                    Some(unsafe { next_key.assume_init() })
                }
            }
            None => {
                let mut key = MaybeUninit::<K>::zeroed();
                if unsafe {
                    bpf_sys::bpf_map_get_next_key(
                        self.map.base.fd,
                        ptr::null(),
                        &mut key as *mut _ as *mut _,
                    )
                } < 0
                {
                    None
                } else {
                    Some(unsafe { key.assume_init() })
                }
            }
        };

        let key = self.key.as_ref()?.clone();
        Some((key.clone(), self.map.get(key).unwrap()))
    }
}

impl StackTrace<'_> {
    pub fn new(map: &Map) -> StackTrace<'_> {
        StackTrace { base: map }
    }

    pub fn get(&mut self, mut id: libc::c_int) -> Option<BpfStackFrames> {
        unsafe {
            let mut value = MaybeUninit::uninit();

            let ret = bpf_sys::bpf_map_lookup_elem(
                self.base.fd,
                &mut id as *mut libc::c_int as _,
                value.as_mut_ptr() as *mut _,
            );

            if ret == 0 {
                Some(value.assume_init())
            } else {
                None
            }
        }
    }

    pub fn delete(&mut self, id: libc::c_int) -> Result<()> {
        unsafe {
            let ret = bpf_sys::bpf_map_delete_elem(
                self.base.fd,
                &id as *const libc::c_int as *mut libc::c_int as _,
            );

            if ret == 0 {
                Ok(())
            } else {
                Err(Error::Map)
            }
        }
    }
}

impl StreamParser {
    /// Attach `sock_map` to stream parser BPF program.
    ///
    /// # Example
    /// ```no_run
    /// use redbpf::{load::Loader, SockMap};
    ///
    /// let loaded = Loader::load(b"echo.elf").expect("error loading BPF program");
    /// let mut echo_sockmap = SockMap::new(loaded.map("echo_sockmap").expect("sockmap not found")).unwrap();
    /// loaded.stream_parsers().next().unwrap().attach_sockmap(&echo_sockmap).expect("Attaching sockmap failed");
    /// ```
    pub fn attach_sockmap(&self, sock_map: &SockMap) -> Result<()> {
        let attach_fd = sock_map.base.fd;
        let prog_fd = self.common.fd.unwrap();

        let ret = unsafe {
            bpf_sys::bpf_prog_attach(
                prog_fd,
                attach_fd,
                bpf_attach_type_BPF_SK_SKB_STREAM_PARSER,
                0,
            )
        };
        if ret < 0 {
            Err(Error::BPF)
        } else {
            Ok(())
        }
    }
}

impl StreamVerdict {
    /// Attach `sock_map` to stream verdict BPF program.
    ///
    /// # Example
    /// ```no_run
    /// use redbpf::{load::Loader, SockMap};
    ///
    /// let loaded = Loader::load(b"echo.elf").expect("error loading BPF program");
    /// let mut echo_sockmap = SockMap::new(loaded.map("echo_sockmap").expect("sockmap not found")).unwrap();
    /// loaded.stream_verdicts().next().unwrap().attach_sockmap(&echo_sockmap).expect("Attaching sockmap failed");
    /// ```
    pub fn attach_sockmap(&self, sock_map: &SockMap) -> Result<()> {
        let attach_fd = sock_map.base.fd;
        let prog_fd = self.common.fd.unwrap();

        let ret = unsafe {
            bpf_sys::bpf_prog_attach(
                prog_fd,
                attach_fd,
                bpf_attach_type_BPF_SK_SKB_STREAM_VERDICT,
                0,
            )
        };
        if ret < 0 {
            Err(Error::BPF)
        } else {
            Ok(())
        }
    }
}

impl<'a> SockMap<'a> {
    pub fn new(map: &'a Map) -> Result<SockMap<'a>> {
        Ok(SockMap { base: map })
    }

    pub fn set(&mut self, mut idx: u32, mut fd: RawFd) -> Result<()> {
        let ret = unsafe {
            bpf_sys::bpf_map_update_elem(
                self.base.fd,
                &mut idx as *mut _ as *mut _,
                &mut fd as *mut _ as *mut _,
                BPF_ANY.into(), // No condition on the existence of the entry for `idx`.
            )
        };
        if ret < 0 {
            Err(Error::Map)
        } else {
            Ok(())
        }
    }

    pub fn delete(&mut self, mut idx: u32) -> Result<()> {
        let ret =
            unsafe { bpf_sys::bpf_map_delete_elem(self.base.fd, &mut idx as *mut _ as *mut _) };
        if ret < 0 {
            Err(Error::Map)
        } else {
            Ok(())
        }
    }
}

#[inline]
fn add_relocation(
    rels: &mut Vec<RelocationInfo>,
    shndx: usize,
    shdr: &SectionHeader,
    shdr_relocs: &[(usize, RelocSection<'_>)],
) {
    // if unwrap blows up, something's really bad
    let section_rels = &shdr_relocs.iter().find(|(idx, _)| idx == &shndx).unwrap().1;
    rels.extend(section_rels.iter().map(|rel| RelocationInfo {
        target_sec_idx: shdr.sh_info as usize,
        sym_idx: rel.r_sym,
        offset: rel.r_offset,
    }));
}

#[inline]
fn get_version(bytes: &[u8]) -> u32 {
    let version = zero::read::<u32>(bytes);
    match version {
        0xFFFF_FFFE => get_kernel_internal_version().unwrap(),
        _ => *version,
    }
}

#[inline]
fn data<'d>(bytes: &'d [u8], shdr: &SectionHeader) -> &'d [u8] {
    let offset = shdr.sh_offset as usize;
    let end = (shdr.sh_offset + shdr.sh_size) as usize;

    &bytes[offset..end]
}
