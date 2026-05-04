//! Parse Go's `.gopclntab` to locate functions in stripped binaries.
//!
//! Even with `-ldflags="-s -w"` the ELF symbol table and DWARF are
//! stripped, but `.gopclntab` survives because the runtime needs it
//! for stack traces and `runtime.FuncForPC`. It contains the same
//! `(function name → entry PC)` mapping the regular symtab would,
//! just in Go's own packed format.
//!
//! Supported magic values (matching Go's `pcHeader.magic`):
//!   - `0xfffffff0` — Go 1.18, 1.19
//!   - `0xfffffff1` — Go 1.20+
//!
//! Older layouts (Go ≤ 1.17, magic `0xfffffffa`) are not handled here.
//! They predate the `textStart`-relative entry-PC encoding, and rare
//! enough on modern clusters that the extra parser branch isn't worth
//! the surface area.
//!
//! Reference: `runtime/symtab.go` in the Go source tree, structs
//! `pcHeader` and `funcInfo`.

use std::{collections::HashMap, fs, path::Path};

use anyhow::{anyhow, bail, Context, Result};
use object::{Object, ObjectSection};

/// Where a Go function lives in the binary. `vaddr` is the virtual
/// address as the loader sees it; `file_offset` is what aya's
/// `UProbe::attach(None, offset, ...)` expects.
#[derive(Debug, Clone, Copy)]
pub struct FuncLocation {
    pub vaddr: u64,
    pub size: u64,
    pub file_offset: u64,
}

/// Look up a set of function names in the binary's `.gopclntab`.
/// Names that don't exist are simply absent from the returned map.
pub fn find_functions(
    binary: &Path,
    needles: &[&str],
) -> Result<HashMap<String, FuncLocation>> {
    let data = fs::read(binary)
        .with_context(|| format!("read {}", binary.display()))?;
    let obj = object::read::File::parse(&*data)
        .map_err(|e| anyhow!("ELF parse: {e}"))?;

    let pcln = obj
        .section_by_name(".gopclntab")
        .context(".gopclntab section not found")?;
    let pcln_data = pcln
        .data()
        .map_err(|e| anyhow!("read .gopclntab: {e}"))?;

    if pcln_data.len() < 72 {
        bail!(".gopclntab too small ({} bytes)", pcln_data.len());
    }

    // Header:
    //   [0..4]  magic
    //   [4..6]  pad
    //   [6]     minLC (instruction quantum, unused here)
    //   [7]     ptrSize
    //   [8..16] nfunc (i64)
    //   ... 7 uintptr fields, each 8 bytes for 64-bit binaries.
    let magic = u32::from_le_bytes(pcln_data[0..4].try_into().unwrap());
    if !matches!(magic, 0xfffffff0 | 0xfffffff1) {
        bail!("unsupported .gopclntab magic {magic:#x}");
    }
    let ptr_size = pcln_data[7];
    if ptr_size != 8 {
        bail!("unsupported gopclntab ptrSize {ptr_size}");
    }

    let nfunc = u64::from_le_bytes(pcln_data[8..16].try_into().unwrap()) as usize;
    let text_start = u64::from_le_bytes(pcln_data[24..32].try_into().unwrap());
    let funcname_off = u64::from_le_bytes(pcln_data[32..40].try_into().unwrap()) as usize;
    let pcln_off = u64::from_le_bytes(pcln_data[64..72].try_into().unwrap()) as usize;

    // The function table at pcln_off has nfunc + 1 entries — the last
    // one is a sentinel whose entryOff marks the end of the last real
    // function (used to compute the trailing function's size).
    let func_table_bytes = (nfunc + 1) * 8;
    if pcln_off
        .checked_add(func_table_bytes)
        .map(|end| end > pcln_data.len())
        .unwrap_or(true)
    {
        bail!("function table overruns .gopclntab");
    }

    // Map vaddr → file_offset via the .text section's loaded address /
    // file range. Every Go function lives in .text on x86_64; if any
    // future runtime split that we'd need to widen the search.
    let text = obj
        .section_by_name(".text")
        .context(".text section not found")?;
    let text_addr = text.address();
    let (text_file_off, _) = text
        .file_range()
        .context(".text has no file range")?;

    let want: std::collections::HashSet<&&str> = needles.iter().collect();
    let mut found = HashMap::new();

    for i in 0..nfunc {
        let entry_pos = pcln_off + i * 8;
        let entry_off =
            u32::from_le_bytes(pcln_data[entry_pos..entry_pos + 4].try_into().unwrap());
        let func_off = u32::from_le_bytes(
            pcln_data[entry_pos + 4..entry_pos + 8].try_into().unwrap(),
        ) as usize;

        // funcInfo layout in pcln_data[pcln_off + func_off..]:
        //   [0..4]  entryOff (duplicate of the table value, ignored)
        //   [4..8]  nameOff (i32, into funcnametab at funcname_off)
        let info_pos = pcln_off + func_off;
        if info_pos + 8 > pcln_data.len() {
            continue;
        }
        let name_off =
            i32::from_le_bytes(pcln_data[info_pos + 4..info_pos + 8].try_into().unwrap());
        if name_off < 0 {
            continue;
        }
        let name_pos = funcname_off + name_off as usize;
        if name_pos >= pcln_data.len() {
            continue;
        }

        // Read null-terminated function name.
        let tail = &pcln_data[name_pos..];
        let n = tail.iter().position(|&b| b == 0).unwrap_or(0);
        if n == 0 {
            continue;
        }
        let name = match std::str::from_utf8(&tail[..n]) {
            Ok(s) => s,
            Err(_) => continue,
        };

        if !want.contains(&name) {
            continue;
        }

        // Size = next entry's entry_off - this entry's. The trailing
        // sentinel entry makes this safe for the final function.
        let next_entry_pos = pcln_off + (i + 1) * 8;
        let next_entry_off = u32::from_le_bytes(
            pcln_data[next_entry_pos..next_entry_pos + 4].try_into().unwrap(),
        );
        if next_entry_off < entry_off {
            // sanity — gopclntab is supposed to be sorted ascending.
            continue;
        }
        let size = (next_entry_off - entry_off) as u64;
        let vaddr = text_start + entry_off as u64;
        let file_offset = vaddr
            .checked_sub(text_addr)
            .map(|d| text_file_off + d)
            .ok_or_else(|| {
                anyhow!("vaddr {vaddr:#x} below .text base {text_addr:#x}")
            })?;

        found.insert(
            name.to_string(),
            FuncLocation { vaddr, size, file_offset },
        );

        if found.len() == needles.len() {
            // Early exit once we've collected everything — pcln walks
            // can be 100k+ entries on a Rancher-sized binary.
            break;
        }
    }

    Ok(found)
}

/// True iff the binary has a `.gopclntab` section. Cheap precheck —
/// non-Go binaries return false in milliseconds without the parser
/// even running.
pub fn looks_like_go(binary: &Path) -> Result<bool> {
    let data = fs::read(binary)?;
    let obj = match object::read::File::parse(&*data) {
        Ok(o) => o,
        Err(_) => return Ok(false),
    };
    Ok(obj.sections().any(|s| matches!(s.name(), Ok(".gopclntab"))))
}
