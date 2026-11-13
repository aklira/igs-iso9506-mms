// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The journals of a domain (ISO 9506-2 clause 23; IEC 61850-8-1 clause 17.3): a journal holds journal entries, in the order they
//! were entered. A journal is bounded: when it is full the oldest entry is discarded, and the entries that remain keep their order.
//! The selection of the entries that a ReadJournal returns is in the server (`server::service`).

use std::collections::VecDeque;

use igs_iso9506_mms_codec::generated::types::JournalEntry;

/// A journal: its entries, the oldest first.
#[derive(Debug, Clone)]
pub struct Journal {
    capacity: usize,
    entries: VecDeque<JournalEntry>,
}

impl Journal {
    /// An empty journal that keeps at most `capacity` entries (at least one).
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            entries: VecDeque::new(),
        }
    }

    /// Enters an entry. The oldest entry is discarded when the journal is full.
    pub fn append(&mut self, entry: JournalEntry) {
        self.entries.push_back(entry);
        while self.entries.len() > self.capacity {
            self.entries.pop_front();
        }
    }

    /// The entries, the oldest first.
    pub fn entries(&self) -> impl Iterator<Item = &JournalEntry> {
        self.entries.iter()
    }

    /// The number of entries held.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the journal holds no entry.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
