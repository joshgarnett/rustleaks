//! Rule-based annotation of every pinned Go API identity.

mod config;
mod detect;
mod other;
mod report;
mod sources;

use super::inventory::{Inventory, Record};
use super::model::Attrs;

pub(super) fn annotation(record: &Record, inventory: &Inventory) -> Result<Attrs, String> {
    let package = record.package.as_str();
    if package.ends_with("/config") {
        return config::annotation(record);
    }
    if package.ends_with("/detect/codec") {
        return detect::codec(record);
    }
    if package.ends_with("/detect") {
        return detect::annotation(record);
    }
    if package.ends_with("/report") {
        return report::annotation(record);
    }
    if package.ends_with("/sources") {
        return sources::annotation(record);
    }
    other::annotation(record, inventory)
}

pub(super) fn member(record: &Record) -> String {
    if record.owner.is_empty() {
        record.name.clone()
    } else {
        format!("{}.{}", record.owner, record.name)
    }
}
