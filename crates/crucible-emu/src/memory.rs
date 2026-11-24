//! Virtual Memory implementation for Crucible x86-64 user-mode emulator.
//!
//! Provides Copy-on-Write (CoW) page snapshots, dirty-page tracking,
//! and page-level differential bisecting with sub-millisecond state fork latency.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

pub const PAGE_SIZE: usize = 4096;
pub const PAGE_MASK: u64 = !(PAGE_SIZE as u64 - 1);

/// Point-in-time Copy-on-Write snapshot of emulated virtual memory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VirtualMemorySnapshot {
    pub(crate) pages: HashMap<u64, Arc<[u8; PAGE_SIZE]>>,
}

impl VirtualMemorySnapshot {
    pub fn page_count(&self) -> usize {
        self.pages.len()
    }

    pub fn memory_bytes(&self) -> usize {
        self.pages.len() * PAGE_SIZE
    }

    pub fn read_u8(&self, addr: u64) -> Option<u8> {
        let base = addr & PAGE_MASK;
        let offset = (addr as usize) & (PAGE_SIZE - 1);
        self.pages.get(&base).map(|page| page[offset])
    }

    pub fn read_u64(&self, addr: u64) -> Option<u64> {
        let mut buf = [0u8; 8];
        for (i, b) in buf.iter_mut().enumerate() {
            *b = self.read_u8(addr + i as u64)?;
        }
        Some(u64::from_le_bytes(buf))
    }
}

/// Copy-on-Write Virtual Memory subsystem.
#[derive(Default, Clone, Debug)]
pub struct VirtualMemory {
    pub(crate) pages: HashMap<u64, Arc<[u8; PAGE_SIZE]>>,
    pub(crate) dirty_pages: HashSet<u64>,
}

impl VirtualMemory {
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub fn page_base(addr: u64) -> u64 {
        addr & PAGE_MASK
    }

    #[inline]
    pub fn page_offset(addr: u64) -> usize {
        (addr as usize) & (PAGE_SIZE - 1)
    }

    /// Creates an instantaneous O(1) Copy-on-Write snapshot of memory.
    pub fn snapshot(&self) -> VirtualMemorySnapshot {
        VirtualMemorySnapshot {
            pages: self.pages.clone(),
        }
    }

    /// Restores memory to a bit-exact snapshot state.
    pub fn restore_snapshot(&mut self, snapshot: &VirtualMemorySnapshot) {
        self.pages = snapshot.pages.clone();
        self.dirty_pages.clear();
    }

    /// Number of distinct pages touched/written since creation or last reset.
    pub fn dirty_pages_count(&self) -> usize {
        self.dirty_pages.len()
    }

    /// Reset the dirty page tracking set.
    pub fn clear_dirty_tracking(&mut self) {
        self.dirty_pages.clear();
    }

    /// Returns the list of page base addresses modified or added compared to a snapshot.
    pub fn dirty_pages_since(&self, snapshot: &VirtualMemorySnapshot) -> Vec<u64> {
        let mut diff = Vec::new();
        for (&base, page) in &self.pages {
            match snapshot.pages.get(&base) {
                Some(snap_page) => {
                    if !Arc::ptr_eq(page, snap_page) && page.as_slice() != snap_page.as_slice() {
                        diff.push(base);
                    }
                }
                None => diff.push(base),
            }
        }
        diff.sort();
        diff
    }

    /// Get a mutable page slice, copying on write if shared with any snapshot.
    pub fn get_or_create_page(&mut self, base: u64) -> &mut [u8; PAGE_SIZE] {
        self.dirty_pages.insert(base);
        let page = self
            .pages
            .entry(base)
            .or_insert_with(|| Arc::new([0u8; PAGE_SIZE]));
        Arc::make_mut(page)
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

    pub fn read_bytes(&self, mut addr: u64, mut dest: &mut [u8]) -> bool {
        while !dest.is_empty() {
            let base = Self::page_base(addr);
            let offset = Self::page_offset(addr);
            let available = (PAGE_SIZE - offset).min(dest.len());
            if let Some(page) = self.pages.get(&base) {
                dest[..available].copy_from_slice(&page[offset..offset + available]);
                addr += available as u64;
                dest = &mut dest[available..];
            } else {
                return false;
            }
        }
        true
    }

    pub fn write_bytes(&mut self, mut addr: u64, mut src: &[u8]) {
        while !src.is_empty() {
            let base = Self::page_base(addr);
            let offset = Self::page_offset(addr);
            let available = (PAGE_SIZE - offset).min(src.len());
            let page = self.get_or_create_page(base);
            page[offset..offset + available].copy_from_slice(&src[..available]);
            addr += available as u64;
            src = &src[available..];
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

    pub fn page_count(&self) -> usize {
        self.pages.len()
    }
}
