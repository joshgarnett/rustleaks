//! Ordered disposition rows and compact annotation attributes.

use std::collections::BTreeSet;

use serde_json::Value;

use super::inventory::Record;
use super::{IDENTITY_SHA256, REVISION};

pub(super) const FINAL: &str = "Final release disposition: the Go-shaped identity is not shipped; its declared idiomatic replacement, tooling role, or product-scope exclusion is final.";

#[derive(Clone)]
pub(super) struct Attrs {
    pub(super) disposition: String,
    pub(super) cluster: String,
    pub(super) crate_name: String,
    pub(super) module: String,
    pub(super) path: String,
    pub(super) publicity: String,
    pub(super) justification: String,
    pub(super) design_evidence: String,
    pub(super) behavior_links: Vec<String>,
    pub(super) manifest_links: Vec<String>,
    pub(super) implementation_status: String,
    pub(super) test_status: String,
    pub(super) evidence_status: String,
    pub(super) implementation_evidence: String,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn attrs(
    disposition: &str,
    cluster: &str,
    crate_name: &str,
    module: &str,
    path: impl Into<String>,
    publicity: &str,
    justification: &str,
    section: &str,
) -> Attrs {
    Attrs {
        disposition: disposition.into(),
        cluster: cluster.into(),
        crate_name: crate_name.into(),
        module: module.into(),
        path: path.into(),
        publicity: publicity.into(),
        justification: justification.into(),
        design_evidence: format!("docs/ARCHITECTURE.md#{section}"),
        behavior_links: Vec::new(),
        manifest_links: Vec::new(),
        implementation_status: "not-applicable".into(),
        test_status: "not-applicable".into(),
        evidence_status: "go-inventoried".into(),
        implementation_evidence: FINAL.into(),
    }
}

impl Attrs {
    pub(super) fn links(mut self, values: &[&str]) -> Self {
        self.behavior_links
            .extend(values.iter().map(|value| (*value).to_owned()));
        self
    }
    pub(super) fn manifests(mut self, values: &[&str]) -> Self {
        self.manifest_links
            .extend(values.iter().map(|value| (*value).to_owned()));
        self
    }
    pub(super) fn tested(mut self, evidence: &str) -> Self {
        self.implementation_status = "implemented".into();
        self.test_status = "passing".into();
        self.evidence_status = "rust-tested".into();
        self.implementation_evidence = evidence.into();
        self
    }
}

pub(super) struct Row {
    record: Record,
    attrs: Attrs,
}

impl Row {
    pub(super) fn new(record: &Record, attrs: Attrs) -> Self {
        Self {
            record: record.clone(),
            attrs,
        }
    }

    fn write(&self, output: &mut String) -> Result<(), String> {
        let links = prefixed(&self.attrs.behavior_links);
        let manifests = prefixed(&self.attrs.manifest_links);
        output.push('{');
        let mut fields = Vec::new();
        fields.push(pair("schema_version", &Value::from(1))?);
        for (key, value) in [
            ("upstream_revision", REVISION),
            ("inventory_identity_set_sha256", IDENTITY_SHA256),
            ("source_key", &self.record.key),
            ("source_identity", &self.record.identity),
            ("source_identity_sha256", &self.record.identity_sha256),
            ("source_package", &self.record.package),
            ("source_kind", &self.record.kind),
            ("disposition", &self.attrs.disposition),
            ("disposition_cluster", &self.attrs.cluster),
            ("rust_crate", &self.attrs.crate_name),
            ("rust_module", &self.attrs.module),
            ("rust_path", &self.attrs.path),
            ("rust_publicity", &self.attrs.publicity),
            ("contract_justification", &self.attrs.justification),
        ] {
            fields.push(pair(key, &Value::String(value.to_string()))?);
        }
        fields.push(pair("behavior_links", &Value::from(links))?);
        fields.push(pair("manifest_links", &Value::from(manifests))?);
        for (key, value) in [
            ("implementation_status", &self.attrs.implementation_status),
            ("test_status", &self.attrs.test_status),
            ("evidence_status", &self.attrs.evidence_status),
            (
                "implementation_evidence",
                &self.attrs.implementation_evidence,
            ),
            ("design_evidence", &self.attrs.design_evidence),
        ] {
            fields.push(pair(key, &Value::String(value.clone()))?);
        }
        output.push_str(&fields.join(","));
        output.push_str("}\n");
        Ok(())
    }
}

fn prefixed(values: &[String]) -> Vec<String> {
    let mut seen = BTreeSet::new();
    std::iter::once("API-ALL-001".to_owned())
        .chain(values.iter().cloned())
        .filter(|value| seen.insert(value.clone()))
        .collect()
}

fn pair(key: &str, value: &Value) -> Result<String, String> {
    Ok(format!(
        "{}:{}",
        serde_json::to_string(key).map_err(|e| e.to_string())?,
        serde_json::to_string(value).map_err(|e| e.to_string())?
    ))
}

pub(super) fn jsonl(rows: &[Row]) -> Result<Vec<u8>, String> {
    let mut output = String::new();
    for row in rows {
        row.write(&mut output)?;
    }
    Ok(output.into_bytes())
}
