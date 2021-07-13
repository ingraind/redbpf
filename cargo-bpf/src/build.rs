// Copyright 2019 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use bpf_sys::headers::build_kernel_version;
use glob::{glob, PatternError};
use std::convert::From;
use std::fmt::{self, Display};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str;
use toml_edit::{Document, Item};

use crate::llvm;
use crate::CommandError;

#[derive(Debug)]
pub enum Error {
    MissingManifest(PathBuf),
    NoPrograms,
    NoLLC,
    NoOPT,
    Compile(String, Option<String>),
    MissingBitcode(String),
    Link(String),
    IOError(io::Error),
    PatternError(PatternError),
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::IOError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Error {
        Error::IOError(error)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Error::*;
        match self {
            MissingManifest(p) => write!(f, "Could not find `Cargo.toml' in {:?}", p),
            NoPrograms => write!(f, "the package doesn't contain any eBPF programs"),
            Compile(p, Some(msg)) => write!(f, "failed to compile the `{}' program: {}", p, msg),
            Compile(p, None) => write!(f, "failed to compile the `{}' program", p),
            MissingBitcode(p) => write!(f, "failed to generate bitcode for the `{}' program", p),
            Link(p) => write!(f, "failed to generate bitcode for the `{}' program", p),
            NoOPT => write!(f, "no usable opt executable found, expecting version 9"),
            NoLLC => write!(f, "no usable llc executable found, expecting version 9"),
            IOError(e) => write!(f, "{}", e),
            PatternError(e) => write!(f, "couldn't list probe files: {}", e),
        }
    }
}

impl From<Error> for CommandError {
    fn from(error: Error) -> CommandError {
        CommandError(error.to_string())
    }
}

fn build_probe(
    cargo: &Path,
    package: &Path,
    target_dir: &Path,
    probe: &str,
    kernel_source_dir: Option<&Path>,
) -> Result<(), Error> {
    fs::create_dir_all(&target_dir)?;
    let target_dir = target_dir.canonicalize().unwrap().join("bpf");
    let artifacts_dir = target_dir.join("programs").join(probe);
    let _ = fs::remove_dir_all(&artifacts_dir);
    fs::create_dir_all(&artifacts_dir)?;

    let mut flags = String::new();
    if let Ok(rf) = std::env::var("RUSTFLAGS") {
        flags.push_str(&rf);
    }
    flags.push_str(" -C embed-bitcode=yes");

    let version = build_kernel_version(kernel_source_dir)
        .map(|mut v| {
            if v.version >= 5 && v.patchlevel >= 7 {
                v.patchlevel = 7;
                v
            } else {
                v
            }
        })
        .map(|v| format!(r#"kernel_version="{}.{}""#, v.version, v.patchlevel))
        .unwrap_or_else(|_| r#"kernel_version="unknown""#.to_string());

    if !Command::new(cargo)
        .current_dir(package)
        .env("RUSTFLAGS", flags)
        .envs(kernel_source_dir.into_iter().map(|p| ("KERNEL_SOURCE", p)))
        .args("rustc --release --features=probes".split(' '))
        .arg("--target-dir")
        .arg(target_dir.to_str().unwrap())
        .arg("--bin")
        .arg(probe)
        .arg("--")
        .arg("--cfg")
        .arg(version)
        .args(
            "--emit=llvm-bc -C panic=abort -C lto -C link-arg=-nostartfiles -C opt-level=3"
                .split(' '),
        )
        .arg("-g") // To generate .BTF section
        .arg("-o")
        .arg(artifacts_dir.join(probe).to_str().unwrap())
        .status()?
        .success()
    {
        return Err(Error::Compile(probe.to_string(), None));
    }

    let mut bc_files: Vec<PathBuf> = fs::read_dir(artifacts_dir.clone())?
        .filter(|e| {
            e.as_ref()
                .unwrap()
                .path()
                .extension()
                .map(|ext| ext == "bc")
                .unwrap_or(false)
        })
        .map(|e| e.as_ref().unwrap().path())
        .collect();
    if bc_files.len() != 1 {
        return Err(Error::MissingBitcode(probe.to_string()));
    }

    let bc_file = bc_files.drain(..).next().unwrap();
    let opt_bc_file = bc_file.with_extension("bc.opt");
    let target = artifacts_dir.join(format!("{}.elf", probe));
    unsafe { llvm::compile(&bc_file, &target, Some(&opt_bc_file)) }.map_err(|msg| {
        Error::Compile(
            probe.into(),
            Some(format!("couldn't process IR file: {}", msg)),
        )
    })?;

    // stripping debug sections is optional process. So don't care its failure.
    let _ = llvm::strip_debug(target);

    Ok(())
}

pub fn build(
    cargo: &Path,
    package: &Path,
    target_dir: &Path,
    probes: Vec<String>,
) -> Result<(), Error> {
    build_ext(cargo, package, target_dir, probes, None)
}

pub fn build_ext(
    cargo: &Path,
    package: &Path,
    target_dir: &Path,
    mut probes: Vec<String>,
    kernel_source_dir: Option<&Path>,
) -> Result<(), Error> {
    let path = package.join("Cargo.toml");
    if !path.exists() {
        return Err(Error::MissingManifest(path));
    }

    if probes.is_empty() {
        let doc = load_package(package)?;
        probes = probe_names(&doc)?
    };

    unsafe { llvm::init() };

    for probe in probes {
        build_probe(cargo, package, &target_dir, &probe, kernel_source_dir.clone())?;
    }

    Ok(())
}

pub fn cmd_build(programs: Vec<String>, target_dir: PathBuf) -> Result<(), CommandError> {
    let current_dir = std::env::current_dir().unwrap();
    Ok(build(
        Path::new("cargo"),
        &current_dir,
        &target_dir,
        programs,
    )?)
}

pub fn probe_files(package: &Path) -> Result<Vec<String>, Error> {
    glob(&format!("{}/src/**/*.rs", &package.to_string_lossy()))
        .map_err(Error::PatternError)
        .map(|iter| {
            iter.filter_map(|entry| entry.ok().map(|path| path.to_string_lossy().into_owned()))
                .collect()
        })
}

fn load_package(package: &Path) -> Result<Document, Error> {
    let path = package.join("Cargo.toml");
    if !path.exists() {
        return Err(Error::MissingManifest(path));
    }

    let data = fs::read_to_string(path).unwrap();
    Ok(data.parse::<Document>().unwrap())
}

fn probe_names(doc: &Document) -> Result<Vec<String>, Error> {
    match &doc["bin"] {
        Item::ArrayOfTables(array) => Ok(array
            .iter()
            .map(|t| t["name"].as_str().unwrap().into())
            .collect()),
        _ => Err(Error::NoPrograms),
    }
}
