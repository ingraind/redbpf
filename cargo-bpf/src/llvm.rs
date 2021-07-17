use anyhow::{anyhow, Result};
use llvm_sys::bit_writer::LLVMWriteBitcodeToFile;
use llvm_sys::core::*;
use llvm_sys::ir_reader::LLVMParseIRInContext;
use llvm_sys::prelude::*;
use llvm_sys::support::LLVMParseCommandLineOptions;
use llvm_sys::target::*;
use llvm_sys::target_machine::*;
use llvm_sys::transforms::ipo::LLVMAddAlwaysInlinerPass;
use llvm_sys::transforms::pass_manager_builder::*;
use llvm_sys::{LLVMAttributeFunctionIndex, LLVMInlineAsmDialect::*};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::Path;
use std::process::Command;
use std::ptr;

pub unsafe fn init() {
    LLVM_InitializeAllTargets();
    LLVM_InitializeAllTargetInfos();
    LLVM_InitializeAllTargetMCs();
    LLVM_InitializeAllAsmPrinters();
    LLVM_InitializeAllAsmParsers();

    let mut args = Vec::new();
    args.push(CString::new("cargo-bpf").unwrap());
    args.push(CString::new(format!("-unroll-threshold={}", std::u32::MAX)).unwrap());
    let args_ptrs = args.iter().map(|s| s.as_ptr()).collect::<Vec<_>>();
    let overview = CString::new("what is this").unwrap();
    LLVMParseCommandLineOptions(args.len() as i32, args_ptrs.as_ptr(), overview.as_ptr());
}

unsafe fn load_module(context: LLVMContextRef, input: &Path) -> Result<LLVMModuleRef> {
    let mut message: *mut c_char = ptr::null_mut();
    let filename = CString::new(input.to_str().unwrap()).unwrap();
    let mut buf: LLVMMemoryBufferRef = ptr::null_mut();
    LLVMCreateMemoryBufferWithContentsOfFile(
        filename.as_ptr(),
        &mut buf as *mut _,
        &mut message as *mut *mut c_char,
    );
    if !message.is_null() {
        return Err(anyhow!(
            "LLVMCreateMemoryBufferWithContentsOfFile failed: {}",
            error_str(message)
        ));
    }

    let mut module: LLVMModuleRef = ptr::null_mut();
    let mut message: *mut c_char = ptr::null_mut();
    LLVMParseIRInContext(
        context,
        buf,
        &mut module as *mut _,
        &mut message as *mut *mut c_char,
    );
    if !message.is_null() {
        return Err(anyhow!(
            "LLVMParseIRInContext failed: {}",
            error_str(message)
        ));
    }

    Ok(module)
}

unsafe fn inject_exit_call(context: LLVMContextRef, func: LLVMValueRef, builder: LLVMBuilderRef) {
    let exit_str = CString::new("exit").unwrap();
    let exit_sig = LLVMFunctionType(LLVMVoidTypeInContext(context), ptr::null_mut(), 0, 0);
    let exit = LLVMGetInlineAsm(
        exit_sig,
        exit_str.as_ptr() as *mut _,
        "exit".len(),
        ptr::null_mut(),
        0,
        0,
        0,
        LLVMInlineAsmDialectATT,
    );

    let block = LLVMGetLastBasicBlock(func);
    let last = LLVMGetLastInstruction(block);
    LLVMPositionBuilderBefore(builder, last);
    let c_str = CString::new("").unwrap();
    LLVMBuildCall(builder, exit, ptr::null_mut(), 0, c_str.as_ptr());
}

pub unsafe fn compile(input: &Path, output: &Path, bc_output: Option<&Path>) -> Result<()> {
    let context = LLVMGetGlobalContext();
    let module = load_module(context, input)?;
    process_ir(context, module)?;
    let ret = compile_module(module, output, bc_output);
    LLVMDisposeModule(module);

    ret
}

/// Strip debug sections from resulting ELF relocatable file
///
/// This removes sections of which name start with `.debug` and their
/// associated relocation sections. But .BTF related sections are not stripped.
///
/// cf) `llvm_sys::debuginfo::LLVMStripModuleDebugInfo` removes BTF sections so do not call it.
pub(crate) fn strip_debug(target: &impl AsRef<Path>) -> Result<()> {
    Command::new("llvm-strip-12")
        .arg("-g")
        .arg(target.as_ref())
        .status()
        .map(|_| ())
        .or_else(|e| Err(anyhow!("llvm-strip failed: {}", e)))
}

pub unsafe fn process_ir(context: LLVMContextRef, module: LLVMModuleRef) -> Result<()> {
    let builder = LLVMCreateBuilderInContext(context);

    let no_inline = CString::new("noinline").unwrap();
    let no_inline_kind = LLVMGetEnumAttributeKindForName(no_inline.as_ptr(), "noinline".len());
    let always_inline = CString::new("alwaysinline").unwrap();
    let always_inline_kind =
        LLVMGetEnumAttributeKindForName(always_inline.as_ptr(), "alwaysinline".len());
    let always_inline_attr = LLVMCreateEnumAttribute(context, always_inline_kind, 0);

    let mut func = LLVMGetFirstFunction(module);
    while !func.is_null() {
        let mut size: libc::size_t = 0;
        let name = CStr::from_ptr(LLVMGetValueName2(func, &mut size as *mut _))
            .to_str()
            .unwrap();
        if !name.starts_with("llvm.") {
            // make sure everything gets inlined as BPF can't do calls to
            // things other than helpers
            LLVMRemoveEnumAttributeAtIndex(func, LLVMAttributeFunctionIndex, no_inline_kind);
            LLVMAddAttributeAtIndex(func, LLVMAttributeFunctionIndex, always_inline_attr);

            if name == "rust_begin_unwind" {
                // inject a BPF exit call in the panic handler to make the program terminate
                inject_exit_call(context, func, builder);
            }
        }
        func = LLVMGetNextFunction(func);
    }

    // This removes .BTF sections. Do not call it.
    // LLVMStripModuleDebugInfo(module);

    Ok(())
}

unsafe fn create_target_machine() -> Result<LLVMTargetMachineRef> {
    let mut error = ptr::null_mut();
    let triple = CString::new("bpf").unwrap();
    let cpu = CString::new("generic").unwrap(); // see llc -march=bpf -mcpu=help
    let features = CString::new("").unwrap(); // see llc -march=bpf -mcpu=help

    let mut target = ptr::null_mut();
    let ret = LLVMGetTargetFromTriple(triple.as_ptr(), &mut target, &mut error);
    if ret == 1 {
        return Err(anyhow!(
            "LLVMGetTargetFromTriple failed: {}",
            error_str(error)
        ));
    }

    let tm = LLVMCreateTargetMachine(
        target,
        triple.as_ptr(),
        cpu.as_ptr(),
        features.as_ptr(),
        LLVMCodeGenOptLevel::LLVMCodeGenLevelAggressive,
        LLVMRelocMode::LLVMRelocDefault,
        LLVMCodeModel::LLVMCodeModelDefault,
    );
    if tm.is_null() {
        return Err(anyhow!("Couldn't create target machine"));
    }

    Ok(tm)
}

unsafe fn compile_module(
    module: LLVMModuleRef,
    output: &Path,
    bc_output: Option<&Path>,
) -> Result<()> {
    let tm = create_target_machine()?;
    let data_layout = LLVMCreateTargetDataLayout(tm);
    LLVMSetModuleDataLayout(module, data_layout);

    let fpm = LLVMCreateFunctionPassManagerForModule(module);
    let mpm = LLVMCreatePassManager();

    LLVMAddAnalysisPasses(tm, fpm);
    LLVMAddAnalysisPasses(tm, mpm);

    // we annotate all functions as always-inline so that we can force-inline
    // them with the always inliner pass
    LLVMAddAlwaysInlinerPass(mpm);

    // NOTE: we should call LLVMAddTargetLibraryInfo() here but there's no way
    // to retrieve the library info for the BPF target using the C API

    // add all the other passes
    let pmb = LLVMPassManagerBuilderCreate();
    LLVMPassManagerBuilderSetOptLevel(pmb, 3);
    LLVMPassManagerBuilderSetSizeLevel(pmb, 0);

    // We already added the AlwaysInliner pass. Ideally we want to set
    // PMB->Inliner = AlwaysInliner but that's not possible with the C API. So
    // here we add _another_ inliner pass that won't actually inline anything,
    // but will cause the PMB to add extra optimization passes that are only
    // turned on if inlining is configured.
    LLVMPassManagerBuilderUseInlinerWithThreshold(pmb, 275);

    // populate the pass managers
    LLVMPassManagerBuilderPopulateFunctionPassManager(pmb, fpm);
    LLVMPassManagerBuilderPopulateModulePassManager(pmb, mpm);

    // run function passes
    LLVMInitializeFunctionPassManager(fpm);
    let mut func = LLVMGetFirstFunction(module);
    while !func.is_null() {
        if LLVMIsDeclaration(func) == 0 {
            LLVMRunFunctionPassManager(fpm, func);
        }
        func = LLVMGetNextFunction(func);
    }
    LLVMFinalizeFunctionPassManager(fpm);

    // run module passes
    LLVMRunPassManager(mpm, module);

    if let Some(output) = bc_output {
        let file_ptr = CString::new(output.to_str().unwrap()).unwrap().into_raw();
        let ret = LLVMWriteBitcodeToFile(module, file_ptr);
        let _ = CString::from_raw(file_ptr);
        if ret == 1 {
            return Err(anyhow!("LLVMWriteBitcodeToFile failed"));
        }
    }

    // emit the code
    let mut error = ptr::null_mut();
    let file_ptr = CString::new(output.to_str().unwrap()).unwrap().into_raw();
    let ret = LLVMTargetMachineEmitToFile(
        tm,
        module,
        file_ptr,
        LLVMCodeGenFileType::LLVMObjectFile,
        &mut error,
    );
    let _ = CString::from_raw(file_ptr);
    if ret == 1 {
        return Err(anyhow!(
            "LLVMTargetMachineEmitToFile failed: {}",
            error_str(error)
        ));
    }

    LLVMPassManagerBuilderDispose(pmb);
    LLVMDisposePassManager(fpm);
    LLVMDisposePassManager(mpm);
    LLVMDisposeTargetMachine(tm);

    Ok(())
}

unsafe fn error_str(ptr: *mut c_char) -> String {
    if ptr.is_null() {
        "unknown error".to_string()
    } else {
        CStr::from_ptr(ptr).to_string_lossy().into_owned()
    }
}
