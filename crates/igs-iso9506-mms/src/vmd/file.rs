// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The virtual file store of a VMD (ISO 9506-2 clause 18; IEC 61850-8-1 clause 23). A file is named by a path of directory names and
//! a file name. A file is read through a file read state machine (FRSM): FileOpen gives it an identifier, FileRead reads the next part
//! of the file, and FileClose ends it. The identifiers are unique for the VMD.

use std::collections::BTreeMap;

/// A file of the store: its content, and its last modification, as its time text (GeneralizedTime).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredFile {
    /// The content, in octets.
    pub content: Vec<u8>,
    /// The time of the last modification, when it is known.
    pub last_modified: Option<String>,
}

/// Why a file operation is refused. The services map each one to its file error (ISO 9506-2 clause 18).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileError {
    /// The file does not exist, or the FRSM identifier is not open.
    NonExistent,
    /// The position is beyond the end of the file.
    PositionInvalid,
    /// The file is open by a FRSM and cannot be deleted.
    Busy,
}

/// An open file: its name, and the position of the next octet to read.
#[derive(Debug, Clone)]
struct OpenFile {
    name: Vec<String>,
    position: usize,
}

/// The files of a VMD and the file read state machines that are open on them.
#[derive(Debug, Clone, Default)]
pub struct FileStore {
    files: BTreeMap<Vec<String>, StoredFile>,
    open: BTreeMap<i64, OpenFile>,
    next_frsm: i64,
}

impl FileStore {
    /// Adds a file, or replaces its content, at this path.
    pub fn add(&mut self, name: Vec<String>, content: Vec<u8>, last_modified: Option<String>) {
        self.files.insert(
            name,
            StoredFile {
                content,
                last_modified,
            },
        );
    }

    /// The file at this path.
    pub fn file(&self, name: &[String]) -> Option<&StoredFile> {
        self.files.get(name)
    }

    /// The files whose path starts with the given components, in the order of their paths, after `continue_after` when it is given.
    /// An empty specification lists every file.
    pub fn list(
        &self,
        specification: &[String],
        continue_after: Option<&[String]>,
    ) -> Vec<(&Vec<String>, &StoredFile)> {
        self.files
            .iter()
            .filter(|(name, _)| name.starts_with(specification))
            .filter(|(name, _)| continue_after.is_none_or(|after| name.as_slice() > after))
            .collect()
    }

    /// FileOpen: starts a read of the file at this position, and returns the FRSM identifier.
    pub fn open(&mut self, name: &[String], initial_position: u64) -> Result<i64, FileError> {
        let size = self.file(name).ok_or(FileError::NonExistent)?.content.len();
        let position = usize::try_from(initial_position).map_err(|_| FileError::PositionInvalid)?;
        if position > size {
            return Err(FileError::PositionInvalid);
        }
        self.next_frsm = self.next_frsm.saturating_add(1);
        let id = self.next_frsm;
        self.open.insert(
            id,
            OpenFile {
                name: name.to_vec(),
                position,
            },
        );
        Ok(id)
    }

    /// The size of the file that an FRSM reads.
    pub fn size_of_open(&self, frsm: i64) -> Result<usize, FileError> {
        let open = self.open.get(&frsm).ok_or(FileError::NonExistent)?;
        Ok(self
            .file(&open.name)
            .ok_or(FileError::NonExistent)?
            .content
            .len())
    }

    /// FileRead: the next part of the file, of at most `limit` octets, and whether more follows.
    pub fn read(&mut self, frsm: i64, limit: usize) -> Result<(Vec<u8>, bool), FileError> {
        let open = self.open.get(&frsm).ok_or(FileError::NonExistent)?;
        let content = &self
            .files
            .get(&open.name)
            .ok_or(FileError::NonExistent)?
            .content;
        let start = open.position.min(content.len());
        let end = start.saturating_add(limit).min(content.len());
        let part = content.get(start..end).unwrap_or_default().to_vec();
        let more = end < content.len();
        if let Some(open) = self.open.get_mut(&frsm) {
            open.position = end;
        }
        Ok((part, more))
    }

    /// FileClose: ends the read of an FRSM.
    pub fn close(&mut self, frsm: i64) -> Result<(), FileError> {
        self.open
            .remove(&frsm)
            .map(|_| ())
            .ok_or(FileError::NonExistent)
    }

    /// FileDelete: removes a file that no FRSM reads.
    pub fn delete(&mut self, name: &[String]) -> Result<(), FileError> {
        if self.open.values().any(|open| open.name == name) {
            return Err(FileError::Busy);
        }
        self.files
            .remove(name)
            .map(|_| ())
            .ok_or(FileError::NonExistent)
    }
}
