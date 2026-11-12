//! Simulated Block Store & Crash Consistency Model.
//!
//! Provides a deterministic NVMe/SSD block device simulator with:
//! - Volatile page cache vs. stable disk persistence.
//! - Strict `fsync`/`flush` durability semantics.
//! - Deterministic crash fault models: torn writes, lost unsynced writes,
//!   reordered writes, and sector bit-corruption.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const SECTOR_SIZE: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StorageError {
    OutOfBounds { offset: u64, capacity: u64 },
    CorruptedSector { sector: u64 },
    IoError(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CrashFault {
    /// Discards all dirty writes currently in volatile cache without persisting.
    LostUnsyncedWrites,
    /// Simulates a mid-write power cut, only writing the first `bytes_written` (< 512) bytes.
    TornWrite { sector: u64, bytes_written: usize },
    /// Persists only a subset of volatile sectors in arbitrary reordered fashion.
    ReorderedWrites { persisted_sectors: Vec<u64> },
    /// Injects bit flips / bad CRC into a specific sector on disk.
    CorruptSector { sector: u64 },
}

/// Simulated Block Device with Volatile Cache and Crash-Consistency Model.
#[derive(Debug, Clone)]
pub struct SimulatedBlockStore {
    capacity_sectors: u64,
    /// Persisted storage on disk (survives crashes)
    stable_sectors: HashMap<u64, [u8; SECTOR_SIZE]>,
    /// Volatile cache (dirty writes not yet flushed with fsync)
    volatile_cache: HashMap<u64, [u8; SECTOR_SIZE]>,
    /// Corrupted sectors that return IoError/CorruptedSector on read
    corrupted_sectors: Vec<u64>,
}

impl SimulatedBlockStore {
    pub fn new(capacity_sectors: u64) -> Self {
        Self {
            capacity_sectors,
            stable_sectors: HashMap::new(),
            volatile_cache: HashMap::new(),
            corrupted_sectors: Vec::new(),
        }
    }

    pub fn capacity_bytes(&self) -> u64 {
        self.capacity_sectors * SECTOR_SIZE as u64
    }

    /// Reads a 512-byte sector. Reads hit volatile cache first, then stable storage, or zero-fill.
    pub fn read_sector(&self, sector: u64) -> Result<[u8; SECTOR_SIZE], StorageError> {
        if sector >= self.capacity_sectors {
            return Err(StorageError::OutOfBounds {
                offset: sector * SECTOR_SIZE as u64,
                capacity: self.capacity_bytes(),
            });
        }

        if self.corrupted_sectors.contains(&sector) {
            return Err(StorageError::CorruptedSector { sector });
        }

        if let Some(data) = self.volatile_cache.get(&sector) {
            return Ok(*data);
        }

        if let Some(data) = self.stable_sectors.get(&sector) {
            return Ok(*data);
        }

        Ok([0u8; SECTOR_SIZE])
    }

    /// Writes a sector to the volatile cache (dirty, not yet fsync'd).
    pub fn write_sector(&mut self, sector: u64, data: &[u8; SECTOR_SIZE]) -> Result<(), StorageError> {
        if sector >= self.capacity_sectors {
            return Err(StorageError::OutOfBounds {
                offset: sector * SECTOR_SIZE as u64,
                capacity: self.capacity_bytes(),
            });
        }

        // Writing heals previous corruption on that sector
        self.corrupted_sectors.retain(|&s| s != sector);
        self.volatile_cache.insert(sector, *data);
        Ok(())
    }

    /// Convenience helper to write arbitrary byte slices across sector boundaries.
    pub fn write_bytes(&mut self, offset: u64, data: &[u8]) -> Result<(), StorageError> {
        let total_bytes = data.len() as u64;
        if offset + total_bytes > self.capacity_bytes() {
            return Err(StorageError::OutOfBounds {
                offset: offset + total_bytes,
                capacity: self.capacity_bytes(),
            });
        }

        let mut written = 0;
        while written < data.len() {
            let curr_offset = offset + written as u64;
            let sector = curr_offset / SECTOR_SIZE as u64;
            let sector_offset = (curr_offset % SECTOR_SIZE as u64) as usize;

            let mut sector_data = self.read_sector(sector)?;
            let to_copy = (SECTOR_SIZE - sector_offset).min(data.len() - written);
            sector_data[sector_offset..sector_offset + to_copy]
                .copy_from_slice(&data[written..written + to_copy]);

            self.write_sector(sector, &sector_data)?;
            written += to_copy;
        }

        Ok(())
    }

    /// Convenience helper to read arbitrary byte slices across sector boundaries.
    pub fn read_bytes(&self, offset: u64, len: usize) -> Result<Vec<u8>, StorageError> {
        if offset + len as u64 > self.capacity_bytes() {
            return Err(StorageError::OutOfBounds {
                offset: offset + len as u64,
                capacity: self.capacity_bytes(),
            });
        }

        let mut result = Vec::with_capacity(len);
        let mut read = 0;
        while read < len {
            let curr_offset = offset + read as u64;
            let sector = curr_offset / SECTOR_SIZE as u64;
            let sector_offset = (curr_offset % SECTOR_SIZE as u64) as usize;

            let sector_data = self.read_sector(sector)?;
            let to_copy = (SECTOR_SIZE - sector_offset).min(len - read);
            result.extend_from_slice(&sector_data[sector_offset..sector_offset + to_copy]);
            read += to_copy;
        }

        Ok(result)
    }

    /// Flushes all dirty volatile cache pages to stable storage (fsync / fdatasync).
    pub fn fsync(&mut self) {
        for (sector, data) in self.volatile_cache.drain() {
            self.stable_sectors.insert(sector, data);
        }
    }

    /// Returns whether there are unflushed dirty writes in cache.
    pub fn has_unflushed_writes(&self) -> bool {
        !self.volatile_cache.is_empty()
    }

    /// Simulates a crash with a specific fault model.
    pub fn crash(&mut self, fault: CrashFault) {
        match fault {
            CrashFault::LostUnsyncedWrites => {
                // All volatile writes vanish on crash
                self.volatile_cache.clear();
            }
            CrashFault::TornWrite { sector, bytes_written } => {
                let bytes = bytes_written.min(SECTOR_SIZE);
                if let Some(dirty_data) = self.volatile_cache.remove(&sector) {
                    let mut stable = self.stable_sectors.get(&sector).copied().unwrap_or([0u8; SECTOR_SIZE]);
                    // Only the first `bytes` of dirty data reached magnetic/NAND media
                    stable[..bytes].copy_from_slice(&dirty_data[..bytes]);
                    self.stable_sectors.insert(sector, stable);
                }
                // Discard remaining unsynced writes
                self.volatile_cache.clear();
            }
            CrashFault::ReorderedWrites { persisted_sectors } => {
                for sector in persisted_sectors {
                    if let Some(dirty_data) = self.volatile_cache.remove(&sector) {
                        self.stable_sectors.insert(sector, dirty_data);
                    }
                }
                // Rest of volatile writes are lost
                self.volatile_cache.clear();
            }
            CrashFault::CorruptSector { sector } => {
                if !self.corrupted_sectors.contains(&sector) {
                    self.corrupted_sectors.push(sector);
                }
                self.volatile_cache.clear();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_basic_read_write() {
        let mut store = SimulatedBlockStore::new(10);
        let data = [42u8; SECTOR_SIZE];
        store.write_sector(0, &data).unwrap();
        assert_eq!(store.read_sector(0).unwrap(), data);
    }

    #[test]
    fn test_storage_fsync_durability_across_crash() {
        let mut store = SimulatedBlockStore::new(10);
        let data1 = [1u8; SECTOR_SIZE];
        let data2 = [2u8; SECTOR_SIZE];

        // Sector 0 is written and fsync'd
        store.write_sector(0, &data1).unwrap();
        store.fsync();

        // Sector 1 is written but NOT fsync'd
        store.write_sector(1, &data2).unwrap();

        // Crash with LostUnsyncedWrites
        store.crash(CrashFault::LostUnsyncedWrites);

        // Sector 0 survived!
        assert_eq!(store.read_sector(0).unwrap(), data1);
        // Sector 1 was lost (reset to zero-fill)
        assert_eq!(store.read_sector(1).unwrap(), [0u8; SECTOR_SIZE]);
    }

    #[test]
    fn test_storage_torn_write_fault() {
        let mut store = SimulatedBlockStore::new(10);
        let mut data = [0xAA; SECTOR_SIZE];
        data[..100].fill(0xFF);

        store.write_sector(3, &data).unwrap();
        // Power cut after only 100 bytes written to sector 3
        store.crash(CrashFault::TornWrite { sector: 3, bytes_written: 100 });

        let read_back = store.read_sector(3).unwrap();
        assert_eq!(&read_back[..100], &[0xFF; 100]);
        assert_eq!(&read_back[100..], &[0x00; 412]); // remaining bytes are old zero-fill
    }

    #[test]
    fn test_storage_corruption_fault() {
        let mut store = SimulatedBlockStore::new(10);
        store.write_sector(5, &[1u8; SECTOR_SIZE]).unwrap();
        store.fsync();

        store.crash(CrashFault::CorruptSector { sector: 5 });
        assert_eq!(store.read_sector(5), Err(StorageError::CorruptedSector { sector: 5 }));
    }

    #[test]
    fn test_storage_write_bytes_crossing_sectors() {
        let mut store = SimulatedBlockStore::new(10);
        let payload = vec![0xBE; 1000]; // spans across sector 0 and sector 1
        store.write_bytes(100, &payload).unwrap();
        store.fsync();

        let read_back = store.read_bytes(100, 1000).unwrap();
        assert_eq!(read_back, payload);
    }

    #[test]
    fn test_storage_reordered_writes_fault() {
        let mut store = SimulatedBlockStore::new(10);
        let data1 = [0x11; SECTOR_SIZE];
        let data2 = [0x22; SECTOR_SIZE];
        let data3 = [0x33; SECTOR_SIZE];

        // Three dirty writes staged in cache
        store.write_sector(1, &data1).unwrap();
        store.write_sector(2, &data2).unwrap();
        store.write_sector(3, &data3).unwrap();

        // Crash occurs where only sector 3 reached disk, 1 and 2 were lost
        store.crash(CrashFault::ReorderedWrites {
            persisted_sectors: vec![3],
        });

        // Sector 3 persisted!
        assert_eq!(store.read_sector(3).unwrap(), data3);
        // Sectors 1 and 2 were lost to power cut
        assert_eq!(store.read_sector(1).unwrap(), [0u8; SECTOR_SIZE]);
        assert_eq!(store.read_sector(2).unwrap(), [0u8; SECTOR_SIZE]);
    }
}
