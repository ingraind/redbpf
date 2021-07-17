// Copyright 2019 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use quote::quote;
use std::env;
use std::fs::File;
use std::io::{self, Write};
use std::path::PathBuf;
use syn::visit::Visit;
use syn::{
    self, parse_str, punctuated::Punctuated, token::Comma, AngleBracketedGenericArguments,
    ForeignItemStatic, GenericArgument, Ident, PathArguments::*, Type,
};

use cargo_bpf_lib::bindgen as bpf_bindgen;

fn create_module(path: PathBuf, name: &str, bindings: &str) -> io::Result<()> {
    let mut file = File::create(path)?;
    writeln!(
        &mut file,
        r"
mod {name} {{
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]
#![allow(unused_unsafe)]
#![allow(clippy::all)]
{bindings}
}}
pub use {name}::*;
",
        name = name,
        bindings = bindings
    )
}

fn rerun_if_changed_dir(dir: &str) {
    println!("cargo:rerun-if-changed={}/", dir);
    glob::glob(&format!("./{}/**/*.h", dir))
        .expect("Failed to glob for source files from build.rs")
        .filter_map(|e| e.ok())
        .for_each(|path| println!("cargo:rerun-if-changed={}", path.to_string_lossy()));
}

fn main() {
    rerun_if_changed_dir("../include");
    rerun_if_changed_dir("../bpf-sys/libbpf/src");

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let types = ["pt_regs", "s32", "bpf_.*"];
    let vars = ["BPF_.*"];
    let xdp_types = [
        "xdp_md",
        "ethhdr",
        "iphdr",
        "ipv6hdr",
        "tcphdr",
        "udphdr",
        "xdp_action",
        "__sk_.*",
        "sk_.*",
        "inet_sock",
        "sockaddr",
        "sockaddr_in",
        "in_addr",
        "tcp.*_sock",
        "udp.*_sock",
        "btf_ptr",
    ];
    let xdp_vars = ["ETH_.*", "IPPROTO_.*", "SOCK_.*", "SK_FL_.*", "AF_.*"];

    let mut builder = bpf_bindgen::builder()
        .header("../include/redbpf_helpers.h")
        .header("../bpf-sys/libbpf/src/bpf_helpers.h");

    for ty in types.iter().chain(xdp_types.iter()) {
        builder = builder.whitelist_type(ty);
    }

    for var in vars.iter().chain(xdp_vars.iter()) {
        builder = builder.whitelist_var(var);
    }

    builder = builder.opaque_type("xregs_state");
    let mut bindings = builder
        .generate()
        .expect("failed to generate bindings")
        .to_string();
    let accessors = bpf_bindgen::generate_read_accessors(
        &bindings,
        &[
            "sock",
            "sockaddr",
            "sockaddr_in",
            "in_addr",
            "file",
            "inode",
            "path",
            "dentry",
            "qstr",
        ],
    );
    bindings.push_str("use crate::helpers::bpf_probe_read;");
    bindings.push_str(&accessors);
    create_module(out_dir.join("gen_bindings.rs"), "gen_bindings", &bindings).unwrap();

    let bindings = bpf_bindgen::builder()
        .header("../include/redbpf_helpers.h")
        .header("../bpf-sys/libbpf/src/bpf_helpers.h")
        .whitelist_var("bpf_.*")
        .generate()
        .expect("Unable to generate bindings!");
    let helpers = gen_helpers(&bindings.to_string());
    create_module(out_dir.join("gen_helpers.rs"), "gen_helpers", &helpers).unwrap();
}

struct RewriteBpfHelpers {
    helpers: Vec<String>,
}

impl Visit<'_> for RewriteBpfHelpers {
    fn visit_foreign_item_static(&mut self, item: &ForeignItemStatic) {
        if let Type::Path(path) = &*item.ty {
            let ident = &item.ident;
            let ident_str = ident.to_string();
            let last = path.path.segments.last().unwrap();
            let ty_ident = last.ident.to_string();
            if ident_str.starts_with("bpf_") && ty_ident == "Option" {
                let fn_ty = match &last.arguments {
                    AngleBracketed(AngleBracketedGenericArguments { args, .. }) => {
                        args.first().unwrap()
                    }
                    _ => panic!(),
                };
                let mut ty_s = quote! {
                    #[inline(always)]
                    pub #fn_ty
                }
                .to_string();
                ty_s = ty_s.replace("fn (", &format!("fn {} (", ident_str));
                let call_idx = self.helpers.len() + 1;
                let args: Punctuated<Ident, Comma> = match fn_ty {
                    GenericArgument::Type(Type::BareFn(f)) => f
                        .inputs
                        .iter()
                        .map(|arg| arg.name.clone().unwrap().0)
                        .collect(),
                    _ => unreachable!(),
                };
                let body = quote! {
                    {
                        let f: #fn_ty = ::core::mem::transmute(#call_idx);
                        f(#args)
                    }
                }
                .to_string();
                ty_s.push_str(&body);
                let mut helper = ty_s;
                if helper.contains("printk") {
                    helper = format!("/* {} */", helper);
                }
                self.helpers.push(helper);
            }
        }
    }
}

fn gen_helpers(helpers: &str) -> String {
    let tree: syn::File = parse_str(&helpers).unwrap();
    let mut tx = RewriteBpfHelpers {
        helpers: Vec::new(),
    };
    tx.visit_file(&tree);
    let mut out = String::new();
    out.push_str("use crate::bindings::*;\n");
    for helper in &tx.helpers {
        out.push_str(helper);
    }

    out
}
