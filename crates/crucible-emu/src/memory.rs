//! Virtual Memory implementation for Crucible x86-64 user-mode emulator.

use std::collections::HashMap;

pub const PAGE_SIZE: usize = 4096;
pub const PAGE_MASK: u64 = !(PAGE_SIZE as u64 - 1);

#[derive(Default, Clone)]
pub struct VirtualMemory {
    pages: HashMap<u64, Box<[u8; PAGE_SIZE]>>,
}

impl VirtualMemory {
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    fn page_base(addr: u64) -> u64 {
        addr & PAGE_MASK
    }

    #[inline]
    fn page_offset(addr: u64) -> usize {
        (addr as usize) & (PAGE_SIZE - 1)
    }

    pub fn get_or_create_page(&mut self, base: u64) -> &mut [u8; PAGE_SIZE] {
        self.pages
            .entry(base)
            .or_insert_with(|| Box::new([0u8; PAGE_SIZE]))
    }

    pub fn read_u8(&self, addr: u64) -> Option<u8> {
        let base = Self::page_base(addr);
        let offset = Self::page_offset(addr);
        self.pages.get(&base).map(|page| page[offset])
    }

    pub fn write_u8(&mut self, addr: u64, val: u8) {
        let base = Self::page_base(addr);
        let offset = Self::page_offset(addr);
        let page = self.get_or_create_page(base);
        page[offset] = val;
    }

    pub fn read_bytes(&self, addr: u64, dest: &mut [u8]) -> bool {
        for (i, byte) in dest.iter_mut().enumerate() {
            if let Some(b) = self.read_u8(addr + i as u64) {
                *byte = b;
            } else {
                return false;
            }
        }
        true
    }

    pub fn write_bytes(&mut self, addr: u64, src: &[u8]) {
        for (i, &byte) in src.iter().enumerate() {
            self.write_u8(addr + i as u64, byte);
        }
    }

    pub fn read_u16(&self, addr: u64) -> Option<u16> {
        let mut buf = [0u8; 2];
        if self.read_bytes(addr, &mut buf) {
            Some(u16::from_le_bytes(buf))
        } else {
            None
        }
    }

    pub fn write_u16(&mut self, addr: u64, val: u16) {
        self.write_bytes(addr, &val.to_le_bytes());
    }

    pub fn read_u32(&self, addr: u64) -> Option<u32> {
        let mut buf = [0u8; 4];
        if self.read_bytes(addr, &mut buf) {
            Some(u32::from_le_bytes(buf))
        } else {
            None
        }
    }

    pub fn write_u32(&mut self, addr: u64, val: u32) {
        self.write_bytes(addr, &val.to_le_bytes());
    }

    pub fn read_u64(&self, addr: u64) -> Option<u64> {
        let mut buf = [0u8; 8];
        if self.read_bytes(addr, &mut buf) {
            Some(u64::from_le_bytes(buf))
        } else {
            None
        }
    }

    pub fn write_u64(&mut self, addr: u64, val: u64) {
        self.write_bytes(addr, &val.to_le_bytes());
    }

    pub fn read_cstring(&self, addr: u64, max_len: usize) -> Option<Vec<u8>> {
        let mut bytes = Vec::new();
        let mut curr = addr;
        for _ in 0..max_len {
            match self.read_u8(curr) {
                Some(0) => return Some(bytes),
                Some(b) => {
                    bytes.push(b);
                    curr += 1;
                }
                None => return None,
            }
        }
        Some(bytes)
    }
}
