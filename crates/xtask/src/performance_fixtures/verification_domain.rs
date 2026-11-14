//! The verifier's independent, fixed development matrix. No fixture constructor
//! or generator dimension constant is used to enumerate this admission domain.

use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug)]
pub(super) enum Spec {
    Boundary {
        anchor: usize,
        split: usize,
        encoded: bool,
        class: &'static str,
        layout: &'static str,
    },
    Density {
        bytes: usize,
        class: &'static str,
        identity: &'static str,
        separator: &'static str,
    },
    Decoded {
        count: usize,
        depth: usize,
        identity: &'static str,
        positive: bool,
    },
    Connection {
        form: &'static str,
        class: &'static str,
    },
    Partition {
        encoded: bool,
    },
}

impl Spec {
    pub(super) fn expected_occurrences(self) -> Option<usize> {
        match self {
            Self::Boundary {
                class: "positive", ..
            }
            | Self::Partition { .. } => Some(1),
            Self::Boundary { .. } => Some(0),
            Self::Density {
                bytes,
                class: "positive",
                ..
            } => Some(bytes / 64),
            Self::Density {
                bytes,
                class: "alternating",
                ..
            } => Some(bytes / 128),
            Self::Density { .. } => Some(0),
            Self::Decoded {
                count,
                positive: true,
                ..
            } => Some(count),
            Self::Decoded { .. } => Some(0),
            Self::Connection { .. } => None,
        }
    }

    pub(super) const fn family(self) -> &'static str {
        match self {
            Self::Boundary { .. } => "systematic-boundaries",
            Self::Density { .. } => "dense-geometric-matrix",
            Self::Decoded { .. } => "single-carrier-many-decoded",
            Self::Connection { .. } => "connection-string-forms",
            Self::Partition { .. } => "reader-partitions",
        }
    }
}

pub(super) fn command_family(manifest_family: &str) -> Result<&'static str, String> {
    match manifest_family {
        "systematic-boundaries" => Ok("boundaries"),
        "dense-geometric-matrix" => Ok("density"),
        "single-carrier-many-decoded" => Ok("decoded-carrier"),
        "connection-string-forms" => Ok("connections"),
        "reader-partitions" => Ok("partitions"),
        _ => Err("unknown manifest family".into()),
    }
}

/// Logical IDs, distinct source byte inputs, successful/error reader schedules.
pub(super) fn counts(family: &str) -> Result<(usize, usize, usize), String> {
    match family {
        "boundaries" => Ok((1_908, 1_908, 0)),
        "density" => Ok((48, 48, 0)),
        "decoded-carrier" => Ok((32, 28, 0)),
        "connections" => Ok((36, 30, 0)),
        "partitions" => Ok((2, 2, 16)),
        _ => Err("unknown inventory family".into()),
    }
}

pub(super) fn required_cases(family: &str) -> Result<BTreeMap<String, Spec>, String> {
    let mut cases = BTreeMap::new();
    match family {
        "boundaries" => {
            for anchor in [4096, 65536, 100000, 125000, 153672, 182344] {
                for (kind, length) in [("raw", 40), ("base64", 56)] {
                    for split in 0..=length {
                        for class in ["positive", "prefix-negative", "internal-negative"] {
                            cases.insert(
                                format!("boundary-{kind}-{anchor}-{split}-{class}-no-lf"),
                                Spec::Boundary {
                                    anchor,
                                    split,
                                    encoded: kind == "base64",
                                    class,
                                    layout: "no-lf",
                                },
                            );
                        }
                    }
                    let neighbor_splits: &[usize] = if kind == "raw" {
                        &[0, 20, 40]
                    } else {
                        &[0, 28, 54, 55, 56]
                    };
                    for &split in neighbor_splits {
                        for layout in ["lf", "crlf", "invalid-bytes"] {
                            cases.insert(
                                format!("boundary-{kind}-{anchor}-{split}-positive-{layout}"),
                                Spec::Boundary {
                                    anchor,
                                    split,
                                    encoded: kind == "base64",
                                    class: "positive",
                                    layout,
                                },
                            );
                        }
                    }
                }
            }
        }
        "density" => {
            for bytes in [32768, 131072, 524288, 2097152] {
                for class in ["positive", "alternating", "negative"] {
                    for identity in ["repeated", "unique"] {
                        for separator in ["lf", "space"] {
                            cases.insert(
                                format!("dense-{bytes}-{class}-{identity}-{separator}"),
                                Spec::Density {
                                    bytes,
                                    class,
                                    identity,
                                    separator,
                                },
                            );
                        }
                    }
                }
            }
        }
        "decoded-carrier" => {
            for count in [1, 16, 256, 4096] {
                for depth in [1, 2] {
                    for identity in ["repeated", "unique"] {
                        for class in ["positive", "negative"] {
                            cases.insert(
                                format!("one-carrier-{count}-depth-{depth}-{identity}-{class}"),
                                Spec::Decoded {
                                    count,
                                    depth,
                                    identity,
                                    positive: class == "positive",
                                },
                            );
                        }
                    }
                }
            }
        }
        "connections" => {
            for form in [
                "uri-userinfo",
                "jdbc-query",
                "odbc-properties",
                "libpq-keyword",
            ] {
                for class in [
                    "literal",
                    "percent-encoded",
                    "empty",
                    "omitted",
                    "environment-placeholder",
                    "template-placeholder",
                    "public-url",
                    "prose",
                    "malformed-delimiter",
                ] {
                    cases.insert(
                        format!("connection-{form}-{class}"),
                        Spec::Connection { form, class },
                    );
                }
            }
        }
        "partitions" => {
            cases.insert(
                "reader-partitions-raw".into(),
                Spec::Partition { encoded: false },
            );
            cases.insert(
                "reader-partitions-base64".into(),
                Spec::Partition { encoded: true },
            );
        }
        _ => return Err("unknown inventory family".into()),
    }
    if cases.len() != counts(family)?.0 {
        return Err("verifier matrix disagrees with its fixed logical case count".into());
    }
    Ok(cases)
}
