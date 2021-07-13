// Copyright 2019 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use crate::uname;

use std::{
    env,
    error::Error,
    fmt::{self, Display},
    path::{Path, PathBuf},
    process::Command,
    str::FromStr,
};

const KCONFIG: &'static str = "include/linux/kconfig.h";
const VERSION_H: &'static str = "include/generated/uapi/linux/version.h";
const LIB_MODULES: &'static str = "/lib/modules";
const ENV_SOURCE_PATH: &'static str = "KERNEL_SOURCE";
const ENV_SOURCE_VERSION: &'static str = "KERNEL_VERSION";

#[derive(Debug)]
pub enum HeadersError {
    NotFound,
}
impl Display for HeadersError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "No headers found")
    }
}
impl Error for HeadersError {}

struct KernelHeaders {
    source: PathBuf,
    build: PathBuf,
}

pub struct KernelVersion {
    pub version: u8,
    pub patchlevel: u8,
    pub sublevel: u8,
}

pub fn prefix_kernel_headers(headers: &[&str]) -> Option<Vec<String>> {
    let KernelHeaders { source, build } = kernel_headers_path().ok()?;
    let mut ret: Vec<String> = Vec::new();
    for header in headers {
        if header.contains("generated") {
            let path = build.join(header);
            ret.push(path.to_string_lossy().into());
            if header.ends_with("generated") {
                ret.push(path.parent().unwrap().to_string_lossy().into());
            }
        } else {
            ret.push(source.join(header).to_string_lossy().into());
        }
    }
    Some(ret)
}

pub fn running_kernel_version() -> Option<String> {
    env::var(ENV_SOURCE_VERSION).ok().or_else(|| {
        uname::uname()
            .ok()
            .map(|u| uname::to_str(&u.release).to_string())
    })
}

pub fn build_kernel_version(source_dir: Option<&Path>) -> Result<KernelVersion, Box<dyn Error>> {
    let KernelHeaders { source: _, build } = if let Some(source_dir) = source_dir {
        KernelHeaders {
            source: source_dir.to_owned(),
            build: source_dir.to_owned(),
        }
    } else {
        kernel_headers_path()?
    };

    let make_db = Command::new("make")
        .arg("-qp")
        .arg("-f")
        .arg(build.join("Makefile"))
        .output()?;
    let reader = String::from_utf8(make_db.stdout)?;

    let mut version = None::<u8>;
    let mut patchlevel = None::<u8>;
    let mut sublevel = None::<u8>;

    for line in reader.lines() {
        let mut var = line.split(" = ");
        match var.next().map(|s| s.trim()) {
            Some("VERSION") => version = var.next().map(u8::from_str).transpose()?,
            Some("PATCHLEVEL") => patchlevel = var.next().map(u8::from_str).transpose()?,
            Some("SUBLEVEL") => sublevel = var.next().map(u8::from_str).transpose()?,
            _ => continue,
        }

        if version.is_some() && patchlevel.is_some() && sublevel.is_some() {
            break;
        }
    }

    Ok(KernelVersion {
        version: version.unwrap(),
        patchlevel: patchlevel.unwrap(),
        sublevel: sublevel.unwrap(),
    })
}

fn kernel_headers_path() -> Result<KernelHeaders, HeadersError> {
    let source_path = env::var(ENV_SOURCE_PATH).ok().map(PathBuf::from);
    let split_source_path = source_path.clone().and_then(split_kernel_headers);

    if split_source_path.is_some() {
        return Ok(split_source_path.unwrap());
    }

    source_path
        .and_then(|s| {
            let path = PathBuf::from(s);

            if path.join(KCONFIG).is_file() {
                Some(KernelHeaders {
                    source: path.clone(),
                    build: path,
                })
            } else {
                None
            }
        })
        .or_else(lib_modules_kernel_headers)
        .ok_or(HeadersError::NotFound)
}

fn lib_modules_kernel_headers() -> Option<KernelHeaders> {
    match running_kernel_version() {
        Some(version) => split_kernel_headers(Path::new(LIB_MODULES).join(version)),
        None => None,
    }
}

fn split_kernel_headers(path: PathBuf) -> Option<KernelHeaders> {
    let mut build = path.join("build");
    let source = path.join("source");
    let source = match (
        source.join(KCONFIG).is_file(),
        build.join(KCONFIG).is_file(),
    ) {
        (true, _) => source,
        (false, true) => build.clone(),
        _ => return None,
    };
    if !build.join(VERSION_H).is_file() {
        build = source.clone()
    };

    Some(KernelHeaders { source, build })
}
