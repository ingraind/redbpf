#![no_std]
#![no_main]
/// tc map sharing example. This program is loaded by `tc filter add ...`
/// command which is executed by `cargo run --example tc-map-share <port>...`
use core::{
    marker::PhantomData,
    mem::{self, MaybeUninit},
    ptr,
};
use memoffset::offset_of;
use redbpf_macros::map;
use redbpf_probes::tc::prelude::*;
use redbpf_probes::tc::{TcAction, TcActionResult};
program!(0xFFFFFFFE, "GPL");

const PIN_GLOBAL_NS: u32 = 2;

/// `bpf_elf_map` struct is defined by tc. It is not required to use the same
/// name, but it is better to do so.
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_elf_map {
    type_: u32,
    size_key: u32,
    size_value: u32,
    max_elem: u32,
    flags: u32,
    id: u32,
    pinning: u32,
}

pub struct TcHashMap<K, V> {
    def: bpf_elf_map,
    _k: PhantomData<K>,
    _v: PhantomData<V>,
}

impl<K, V> TcHashMap<K, V> {
    /// Creates a map with the specified maximum number of elements.
    pub const fn with_max_entries(max_entries: u32) -> Self {
        Self {
            def: bpf_elf_map {
                type_: bpf_map_type_BPF_MAP_TYPE_HASH,
                size_key: mem::size_of::<K>() as u32,
                size_value: mem::size_of::<V>() as u32,
                max_elem: max_entries,
                flags: 0,
                id: 0,
                pinning: PIN_GLOBAL_NS,
            },
            _k: PhantomData,
            _v: PhantomData,
        }
    }
    /// Returns a reference to the value corresponding to the key.
    #[inline]
    pub fn get(&mut self, key: &K) -> Option<&V> {
        unsafe {
            let value = bpf_map_lookup_elem(
                &mut self.def as *mut _ as *mut _,
                key as *const _ as *const _,
            );
            if value.is_null() {
                None
            } else {
                Some(&*(value as *const V))
            }
        }
    }

    #[inline]
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        unsafe {
            let value = bpf_map_lookup_elem(
                &mut self.def as *mut _ as *mut _,
                key as *const _ as *const _,
            );
            if value.is_null() {
                None
            } else {
                Some(&mut *(value as *mut V))
            }
        }
    }

    /// Set the `value` in the map for `key`
    #[inline]
    pub fn set(&mut self, key: &K, value: &V) {
        unsafe {
            bpf_map_update_elem(
                &mut self.def as *mut _ as *mut _,
                key as *const _ as *const _,
                value as *const _ as *const _,
                BPF_ANY.into(),
            );
        }
    }

    /// Delete the entry indexed by `key`
    #[inline]
    pub fn delete(&mut self, key: &K) {
        unsafe {
            bpf_map_delete_elem(
                &mut self.def as *mut _ as *mut _,
                key as *const _ as *const _,
            );
        }
    }
}

/// key = port, value = blocked packet count
#[map(link_section = "maps")]
static mut blocked_packets: TcHashMap<u16, u64> = TcHashMap::<u16, u64>::with_max_entries(1024);

/// BPF program type is BPF_PROG_TYPE_SCHED_CLS
#[tc_action]
fn block_ports(skb: SkBuff) -> TcActionResult {
    let tcp_hdr_offset = match u32::from_be(unsafe { *skb.skb }.protocol << 16) {
        ETH_P_IP => {
            let mut uninit = MaybeUninit::<iphdr>::uninit();
            if unsafe {
                bpf_skb_load_bytes(
                    skb.skb as *const _,
                    mem::size_of::<ethhdr>() as u32,
                    uninit.as_mut_ptr() as *mut _,
                    mem::size_of::<iphdr>() as u32,
                )
            } < 0
            {
                return Ok(TcAction::Ok);
            }
            let ipv4_hdr = unsafe { uninit.assume_init() };
            if !(ipv4_hdr.version() == 4 && IPPROTO_TCP == ipv4_hdr.protocol as u32) {
                return Ok(TcAction::Ok);
            }
            let iphdr_len = ipv4_hdr.ihl() as usize * 4;
            mem::size_of::<ethhdr>() + iphdr_len
        }
        ETH_P_IPV6 => {
            // following chain of extension headers is not implemented here
            let nexthdr =
                skb.load::<u8>(mem::size_of::<ethhdr>() + offset_of!(ipv6hdr, nexthdr))?;
            if IPPROTO_TCP != nexthdr as u32 {
                return Ok(TcAction::Ok);
            }
            mem::size_of::<ethhdr>() + mem::size_of::<ipv6hdr>()
        }
        _ => return Ok(TcAction::Ok),
    };
    let port = skb.load::<u16>(tcp_hdr_offset + offset_of!(tcphdr, dest))?;
    if let Some(cnt) = unsafe { blocked_packets.get_mut(&port) } {
        trace_print(b"blocked port: ", port);
        *cnt += 1;
        Ok(TcAction::Shot)
    } else {
        trace_print(b"passed port: ", port);
        Ok(TcAction::Ok)
    }
}

fn hex_u8(v: u8, buf: &mut [u8]) {
    let w = v / 0x10;
    buf[0] = if w < 0xa { w + b'0' } else { w - 0xa + b'a' };
    let u = v % 0x10;
    buf[1] = if u < 0xa { u + b'0' } else { u - 0xa + b'a' };
}

fn hex_bytes(arr: &[u8], buf: &mut [u8]) -> usize {
    let mut pos = 0;
    for (i, b) in arr.iter().enumerate() {
        if i != 0 {
            buf[pos] = b' ';
            pos += 1;
        }
        hex_u8(*b, &mut buf[pos..pos + 2]);
        pos += 2;
    }
    pos
}

fn trace_print<T>(msg: &[u8], x: T) {
    let mut buf = [0u8; 128];
    let mut pos = 0;
    for c in msg {
        buf[pos] = *c;
        pos += 1;
    }

    let ptr = &x as *const T as *const usize as usize;
    let sz = mem::size_of::<T>();
    let mut arr = [0u8; 64];
    for i in 0..sz {
        arr[i] = unsafe { ptr::read((ptr + i) as *const usize as *const u8) };
    }

    pos += hex_bytes(&arr[..sz], &mut buf[pos..]);
    buf[pos] = b'\n';
    pos += 2;

    bpf_trace_printk(&buf[..pos]);
}
