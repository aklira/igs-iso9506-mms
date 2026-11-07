// SPDX-FileCopyrightText: 2026 The igs-iso9506-mms contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Every test named in the supported-service matrix of `docs/capabilities.md` (task X3) exists.
//!
//! The matrix is the section between the markers `<!-- matrix:begin -->` and `<!-- matrix:end -->`. A name in
//! it is a code span with an underscore, such as `read_returns_the_values`: it is a test, a Rust `fn` of the
//! crates or a Python `def` of the bench tests. A name without underscore is a service or a CBB, not checked.
//! The check reads the repository only, so it runs in CI, where the licensed standards are absent.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const BEGIN: &str = "<!-- matrix:begin -->";
const END: &str = "<!-- matrix:end -->";

/// The identifiers in code spans of the section that contain an underscore.
fn test_names(section: &str) -> BTreeSet<String> {
    section
        .split('`')
        .enumerate()
        .filter(|(index, _)| index % 2 == 1)
        .map(|(_, span)| span)
        .filter(|span| {
            span.contains('_')
                && span
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        })
        .map(str::to_string)
        .collect()
}

/// The text of every Rust source under `crates/` and every Python test under `bench/tests/`.
fn sources(root: &Path) -> String {
    let mut text = String::new();
    let mut pending = vec![root.join("crates"), root.join("bench/tests")];
    while let Some(path) = pending.pop() {
        let Ok(entries) = fs::read_dir(&path) else {
            continue;
        };
        for entry in entries.flatten() {
            let path: PathBuf = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else if matches!(path.extension().and_then(|e| e.to_str()), Some("rs" | "py")) {
                text.push_str(&fs::read_to_string(&path).unwrap());
                text.push('\n');
            }
        }
    }
    text
}

#[test]
fn every_test_named_in_the_matrix_exists() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let document = fs::read_to_string(root.join("docs/capabilities.md")).unwrap();
    let begin = document.find(BEGIN).expect("the matrix begins");
    let end = document.find(END).expect("the matrix ends");
    let names = test_names(&document[begin..end]);
    assert!(
        names.len() >= 30,
        "the matrix names its tests: {}",
        names.len()
    );

    let text = sources(&root);
    let missing: Vec<&String> = names
        .iter()
        .filter(|name| {
            !text.contains(&format!("fn {name}(")) && !text.contains(&format!("def {name}("))
        })
        .collect();
    assert!(
        missing.is_empty(),
        "named in the matrix but not found: {missing:?}"
    );
}

#[test]
fn a_name_without_an_underscore_or_outside_the_span_is_not_taken_for_a_test() {
    let section = "| `read` | `Read` | `vnam` and `some_test` | plain text_with_underscore |";
    let names = test_names(section);
    assert_eq!(
        names.into_iter().collect::<Vec<_>>(),
        vec!["some_test".to_string()]
    );
}
