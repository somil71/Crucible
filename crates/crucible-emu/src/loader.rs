//! ELF64 Loader for Crucible user-mode x86-64 emulator.

use crate::memory::VirtualMemory;
use object::Object;
use thiserror::Error;

pub const AT_NULL: u64 = 0;
pub const AT_PHDR: u64 = 3;
pub const AT_PHENT: u64 = 4;
pub const AT_PHNUM: u64 = 5;
pub const AT_PAGESZ: u64 = 6;
pub const AT_ENTRY: u64 = 9;
pub const AT_RANDOM: u64 = 25;

#[derive(Debug, Error)]
pub enum LoaderError {
    #[error("Failed to parse ELF binary: {0}")]
    ParseError(#[from] object::Error),
    #[error("Not a 64-bit x86-64 ELF binary")]
    UnsupportedArchitecture,
}

pub struct LoadedBinary {
    pub entry_point: u64,
    pub stack_pointer: u64,
    pub brk_start: u64,
}

fn push_stack(mem: &mut VirtualMemory, sp: &mut u64, val: u64) {
    *sp -= 8;
    mem.write_u64(*sp, val);
}

pub fn load_elf(data: &[u8], mem: &mut VirtualMemory) -> Result<LoadedBinary, LoaderError> {
    let elf = object::File::parse(data)?;
    let entry = elf.entry();
    let mut max_vaddr = 0u64;

    use object::ObjectSegment;
    for segment in elf.segments() {
        let vaddr = segment.address();
        let size = segment.size();
        let data = segment.data()?;

        if size > 0 {
            mem.write_bytes(vaddr, data);
            let end = vaddr + size;
            if end > max_vaddr {
                max_vaddr = end;
            }
        }
    }

    // Align brk_start to next 4096-byte page
    let brk_start = (max_vaddr + 0xfff) & !0xfff;

    // Parse phdr information for auxiliary vector
    let (phdr_addr, phent_size, phnum) = if data.len() >= 64 {
        let phoff = u64::from_le_bytes(data[32..40].try_into().unwrap_or([0; 8]));
        let phent = u16::from_le_bytes(data[54..56].try_into().unwrap_or([0; 2])) as u64;
        let phn = u16::from_le_bytes(data[56..58].try_into().unwrap_or([0; 2])) as u64;
        let mut phdr_vaddr = 0x400000 + phoff;
        for i in 0..phn as usize {
            let offset = (phoff as usize) + i * (phent as usize);
            if offset + 56 <= data.len() {
                let p_type = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
                let p_vaddr = u64::from_le_bytes(data[offset + 16..offset + 24].try_into().unwrap());
                if p_type == 6 {
                    phdr_vaddr = p_vaddr;
                    break;
                }
            }
        }
        (phdr_vaddr, phent, phn)
    } else {
        (0, 56, 0)
    };

    // Set up Linux x86-64 User Stack (default 8MB top at 0x7ffffffde000)
    let stack_top = 0x7ffffffde000u64;
    let mut sp = stack_top;

    // Store strings at top of stack
    let prog_name = b"crucible_target\0";
    sp -= prog_name.len() as u64;
    let prog_name_addr = sp;
    mem.write_bytes(prog_name_addr, prog_name);

    // 16-byte random seed for AT_RANDOM
    let random_bytes = [0x42u8; 16];
    sp -= 16;
    let random_addr = sp;
    mem.write_bytes(random_addr, &random_bytes);

    // Align SP to 16 bytes before vector
    sp &= !0x0f;

    // Push Auxiliary Vector (auxv)
    push_stack(mem, &mut sp, 0); // AT_NULL
    push_stack(mem, &mut sp, 0);

    push_stack(mem, &mut sp, entry); // AT_ENTRY
    push_stack(mem, &mut sp, AT_ENTRY);

    push_stack(mem, &mut sp, 4096); // AT_PAGESZ
    push_stack(mem, &mut sp, AT_PAGESZ);

    push_stack(mem, &mut sp, phdr_addr); // AT_PHDR
    push_stack(mem, &mut sp, AT_PHDR);

    push_stack(mem, &mut sp, phent_size); // AT_PHENT
    push_stack(mem, &mut sp, AT_PHENT);

    push_stack(mem, &mut sp, phnum); // AT_PHNUM
    push_stack(mem, &mut sp, AT_PHNUM);

    push_stack(mem, &mut sp, random_addr); // AT_RANDOM
    push_stack(mem, &mut sp, AT_RANDOM);

    // Environment pointers (NULL-terminated)
    push_stack(mem, &mut sp, 0); // envp[0] = NULL

    // Argument pointers (NULL-terminated)
    push_stack(mem, &mut sp, 0); // argv[1] = NULL
    push_stack(mem, &mut sp, prog_name_addr); // argv[0]

    // argc = 1
    push_stack(mem, &mut sp, 1);

    Ok(LoadedBinary {
        entry_point: entry,
        stack_pointer: sp,
        brk_start,
    })
}
