use super::boundaries::{Layout, Mutation, boundary, partition};
use super::density::{Density, decoded, dense};
use super::*;

#[test]
fn seeded_values_are_domain_separated_and_only_use_the_declared_alphabet() {
    let value = seeded_value("boundary", 1, 4096);
    assert_eq!(value, seeded_value("boundary", 1, 4096));
    assert!(value.iter().all(u8::is_ascii_alphanumeric));
    assert_ne!(value, seeded_value("boundary", 2, 4096));
    assert_ne!(value, seeded_value("density", 1, 4096));
    assert_eq!(pat("boundary", 1).len(), 40);
    assert_eq!(&pat("boundary", 1)[4..], &value[..36]);
}

#[test]
fn every_raw_and_encoded_split_keeps_exact_physical_positions() {
    for encoded in [false, true] {
        let carrier_len = if encoded { 56 } else { 40 };
        for split in 0..=carrier_len {
            for mutation in [
                Mutation::Positive,
                Mutation::Prefix,
                Mutation::InternalSeparator,
            ] {
                let fixture = boundary(4096, split, encoded, mutation, Layout::NoLf);
                fixture.validate_construction().unwrap();
                let manifest = fixture.manifest();
                assert_eq!(manifest["details"]["carrier_bytes"]["start"], 4096 - split);
                assert_eq!(
                    manifest["details"]["carrier_bytes"]["end"],
                    4096 - split + carrier_len
                );
                let count = usize::from(matches!(mutation, Mutation::Positive));
                assert_eq!(fixture.plants.len(), count);
                if count == 1 {
                    let plant = &fixture.plants[0];
                    assert_eq!(
                        plant.span,
                        if encoded {
                            0..40
                        } else {
                            4096 - split..4096 - split + 40
                        }
                    );
                    assert_eq!(
                        manifest["plants"][0]["source_carrier_position"]["start"]["byte_column"],
                        4097 - split
                    );
                }
            }
        }
    }
}

#[test]
fn padding_splits_and_neighbors_retain_independent_source_and_decoded_spans() {
    for split in [54, 55] {
        for layout in [Layout::NoLf, Layout::Lf, Layout::Crlf, Layout::InvalidBytes] {
            let fixture = boundary(65536, split, true, Mutation::Positive, layout);
            fixture.validate_construction().unwrap();
            let outer = fixture.outer.clone().unwrap();
            assert_eq!(&fixture.input[outer.end - 2..outer.end], b"==");
            assert_eq!(outer.start + split, 65536);
            let manifest = fixture.manifest();
            assert_eq!(manifest["details"]["padding_split_probe"], true);
            assert!(manifest["plants"][0]["physical_source_secret_bytes"].is_null());
            assert_eq!(
                manifest["plants"][0]["plaintext_secret_bytes"],
                interval(&(0..40))
            );
        }
    }
}

#[test]
fn construction_validation_rejects_changed_bytes_and_missing_occurrences() {
    let mut fixture = dense(64 * 8, Density::Positive, false, true);
    fixture.validate_construction().unwrap();
    fixture.input[fixture.plants[0].span.start] = b'z';
    assert!(fixture.validate_construction().is_err());
    let mut fixture = dense(64 * 8, Density::Positive, false, true);
    fixture.plants.remove(0);
    assert!(fixture.validate_construction().is_err());
    let mut fixture = decoded(16, 2, false, true);
    fixture.input[fixture.outer.as_ref().unwrap().start] ^= 1;
    assert!(fixture.validate_construction().is_err());
}

#[test]
fn serialized_manifest_verification_reads_literal_bytes_and_detects_tampering() {
    for fixture in [
        dense(32768, Density::Alternating, false, true),
        decoded(16, 2, false, true),
        decoded(16, 1, true, false),
        connections::connection("libpq-keyword", "literal", 27),
    ] {
        let manifest = fixture.manifest();
        verification::verify_bytes(&fixture.input, &manifest).unwrap();
        let mut changed = fixture.input.clone();
        changed[0] ^= 1;
        assert!(verification::verify_bytes(&changed, &manifest).is_err());
        if !fixture.plants.is_empty() {
            let mut wrong_span = manifest.clone();
            wrong_span["plants"][0]["plaintext_secret_bytes"]["start"] = json!(0);
            assert!(verification::verify_bytes(&fixture.input, &wrong_span).is_err());
            let mut wrong_position = manifest.clone();
            wrong_position["plants"][0]["source_carrier_position"]["start"]["byte_column"] =
                json!(0);
            assert!(verification::verify_bytes(&fixture.input, &wrong_position).is_err());
        }
    }
}

#[test]
fn physical_coordinate_oracles_have_literal_lf_crlf_adjacent_lf_and_eof_answers() {
    let bytes = b"a\r\n\n\xffb\n";
    let expected = [
        (1, 1),
        (1, 2),
        (1, 3),
        (2, 1),
        (3, 1),
        (3, 2),
        (3, 3),
        (4, 1),
    ];
    let walked = verification::walk_positions(bytes, 0..=7).unwrap();
    for (offset, expected) in expected.into_iter().enumerate() {
        assert_eq!(walked[&offset], expected);
        let generated = physical_position(&newline_offsets(bytes), &(offset..offset));
        assert_eq!(
            generated["start"],
            json!({"line": expected.0, "byte_column": expected.1})
        );
    }
    assert!(verification::walk_positions(bytes, [8]).is_err());
    for layout in [Layout::Lf, Layout::Crlf] {
        let raw = boundary(4096, 20, false, Mutation::Positive, layout);
        let raw_manifest = raw.manifest();
        assert_eq!(
            raw_manifest["plants"][0]["source_carrier_position"],
            json!({
                "start": {"line": 65, "byte_column": 1},
                "end_exclusive": {"line": 65, "byte_column": 41}
            })
        );
        verification::verify_bytes(&raw.input, &raw_manifest).unwrap();
        let encoded = boundary(65536, 54, true, Mutation::Positive, layout);
        let encoded_manifest = encoded.manifest();
        assert_eq!(
            encoded_manifest["plants"][0]["source_carrier_position"],
            json!({
                "start": {"line": 1025, "byte_column": 1},
                "end_exclusive": {"line": 1025, "byte_column": 57}
            })
        );
        assert_eq!(
            encoded_manifest["plants"][0]["plaintext_position"],
            json!({
                "start": {"line": 1, "byte_column": 1},
                "end_exclusive": {"line": 1, "byte_column": 41}
            })
        );
        verification::verify_bytes(&encoded.input, &encoded_manifest).unwrap();
    }
}

#[test]
fn verifier_rejects_split_identity_geometry_and_timing_metadata_forgery() {
    let fixture = boundary(65536, 55, true, Mutation::Positive, Layout::NoLf);
    let manifest = fixture.manifest();
    verification::verify_bytes(&fixture.input, &manifest).unwrap();
    for (key, forged) in [
        ("split_offset_in_carrier", json!(54)),
        ("anchor_byte", json!(65537)),
        ("padding_split_probe", json!(false)),
        ("carrier_length", json!(55)),
        ("layout", json!("lf")),
    ] {
        let mut wrong = manifest.clone();
        wrong["details"][key] = forged;
        assert!(
            verification::verify_bytes(&fixture.input, &wrong).is_err(),
            "{key}"
        );
    }
    let fixture = dense(32768, Density::Alternating, false, true);
    let manifest = fixture.manifest();
    verification::verify_bytes(&fixture.input, &manifest).unwrap();
    for (key, forged) in [
        ("record_bytes", json!(128)),
        ("records", json!(256)),
        ("identity_pattern", json!("repeated")),
        ("class", json!("positive")),
        ("single_line_timing_cap_input_bytes", json!(2_097_152)),
        ("literal_line_payload_upper_bound_bytes", json!(0)),
    ] {
        let mut wrong = manifest.clone();
        wrong["details"][key] = forged;
        assert!(
            verification::verify_bytes(&fixture.input, &wrong).is_err(),
            "{key}"
        );
    }
    let fixture = decoded(4096, 2, false, false);
    let mut manifest = fixture.manifest();
    verification::verify_bytes(&fixture.input, &manifest).unwrap();
    manifest["timing_eligible_after_scope_and_quality_gate"] = json!(true);
    assert!(verification::verify_bytes(&fixture.input, &manifest).is_err());
    manifest["timing_eligible_after_scope_and_quality_gate"] = json!(false);
    manifest["details"]["timed_inner_record_cap"] = json!(4096);
    assert!(verification::verify_bytes(&fixture.input, &manifest).is_err());
}

#[test]
fn verifier_rejects_overlapping_truncated_wrong_size_and_false_complete_read_schedules() {
    boundaries::generate_partitions(&mut |fixture| {
        let manifest = fixture.manifest();
        verification::verify_bytes(&fixture.input, &manifest)?;
        let mut overlap = manifest.clone();
        overlap["details"]["reader_schedules"][0]["partitions"][1]["start"] = json!(0);
        assert!(verification::verify_bytes(&fixture.input, &overlap).is_err());
        let mut truncated = manifest.clone();
        assert!(
            truncated["details"]["reader_schedules"][0]["partitions"]
                .as_array_mut()
                .unwrap()
                .pop()
                .is_some()
        );
        assert!(verification::verify_bytes(&fixture.input, &truncated).is_err());
        let mut wrong_size = manifest.clone();
        wrong_size["details"]["reader_schedules"][2]["partitions"][0]["end"] = json!(6);
        assert!(verification::verify_bytes(&fixture.input, &wrong_size).is_err());
        let mut zero_read = manifest.clone();
        zero_read["details"]["reader_schedules"][0]["cyclic_successful_read_sizes"][0] = json!(0);
        assert!(verification::verify_bytes(&fixture.input, &zero_read).is_err());
        let mut false_complete = manifest.clone();
        false_complete["details"]["error_schedules"][2]["expected_status"] = json!("complete");
        assert!(verification::verify_bytes(&fixture.input, &false_complete).is_err());
        Ok(())
    })
    .unwrap();
}

fn density_inventory_control() -> Value {
    inventory_control("density")
}

fn inventory_control(family: &str) -> Value {
    let (logical, distinct, schedules) = verification_domain::counts(family).unwrap();
    let cases = verification_domain::required_cases(family)
        .unwrap()
        .iter()
        .map(|(id, spec)| {
            let identity = match spec {
                verification_domain::Spec::Connection {
                    class: "public-url",
                    ..
                } => "public-url".to_owned(),
                verification_domain::Spec::Connection { class: "prose", .. } => "prose".to_owned(),
                verification_domain::Spec::Decoded { count: 1, .. } => {
                    id.replace("repeated", "unique")
                }
                _ => id.clone(),
            };
            json!({
                "id": id, "input_sha256": sha256_bytes(identity.as_bytes()),
                "input_bytes": 0, "expected_occurrences": spec.expected_occurrences(),
                "manifest_path": format!("answers/{id}.json"),
                "manifest_sha256": sha256_bytes(id.as_bytes())
            })
        })
        .collect::<Vec<_>>();
    json!({
        "schema": "rustleaks.development-fixtures.v1",
        "family": family, "domain": "full-family-v1", "partition": "development",
        "development_seed": DEVELOPMENT_SEED,
        "alphabet": String::from_utf8_lossy(ALPHABET),
        "seed_recipe": "SHA256(seed || NUL || family || NUL || development || NUL || decimal-ordinal || NUL || decimal-counter); reject bytes >= 248; map accepted bytes modulo 62",
        "logical_case_count": logical, "distinct_input_count": distinct, "reader_schedule_expectations": schedules,
        "scanners_invoked": false, "measurements_run": false, "construction_only": true,
        "input_scope": "each inputs/<case>/ directory independently; never scan the bundle root or answers",
        "cases": cases,
    })
}

#[test]
fn verifier_rejects_absent_nullable_oracle_fields_and_changed_policy_contracts() {
    let connection = connections::connection("uri-userinfo", "literal", 0);
    let manifest = connection.manifest();
    verification::verify_bytes(&connection.input, &manifest).unwrap();
    for key in [
        "expected_canonical_family",
        "expected_occurrences",
        "expected_unique_values",
        "physical_source_encoded_carrier_bytes",
    ] {
        let mut missing = manifest.clone();
        assert!(missing.as_object_mut().unwrap().remove(key).is_some());
        assert!(
            verification::verify_bytes(&connection.input, &missing).is_err(),
            "{key}"
        );
    }
    let mut changed_identity = manifest.clone();
    changed_identity["rule_identity_contract"] = json!("ignore-native-rule-identifiers");
    assert!(verification::verify_bytes(&connection.input, &changed_identity).is_err());
    let mut missing_identity = manifest;
    assert!(
        missing_identity
            .as_object_mut()
            .unwrap()
            .remove("rule_identity_contract")
            .is_some()
    );
    assert!(verification::verify_bytes(&connection.input, &missing_identity).is_err());

    let fixture = decoded(16, 1, false, true);
    let mut missing_span = fixture.manifest();
    assert!(
        missing_span["plants"][0]
            .as_object_mut()
            .unwrap()
            .remove("physical_source_secret_bytes")
            .is_some()
    );
    assert!(verification::verify_bytes(&fixture.input, &missing_span).is_err());
    let mut missing_reason = fixture.manifest();
    assert!(
        missing_reason["details"]
            .as_object_mut()
            .unwrap()
            .remove("untimed_reason")
            .is_some()
    );
    assert!(verification::verify_bytes(&fixture.input, &missing_reason).is_err());

    let inventory = inventory_control("connections");
    verification::verify_inventory(&inventory).unwrap();
    let mut missing_count = inventory.clone();
    assert!(
        missing_count["cases"][0]
            .as_object_mut()
            .unwrap()
            .remove("expected_occurrences")
            .is_some()
    );
    assert!(verification::verify_inventory(&missing_count).is_err());
}

#[test]
fn verifier_rejects_seed_substitution_with_self_consistent_values_spans_and_hashes() {
    let mut fixture = boundary(4096, 20, false, Mutation::Positive, Layout::NoLf);
    let mut substituted = b"ghp_".to_vec();
    substituted.extend(std::iter::repeat_n(b'A', 36));
    let span = fixture.plants[0].span.clone();
    fixture.input[span].copy_from_slice(&substituted);
    fixture.plants[0].value = substituted;
    // The literal plant and all serialized hashes now agree with the changed
    // input, but the independent seed contract must still reject it.
    fixture.validate_construction().unwrap();
    let manifest = fixture.manifest();
    assert_eq!(manifest["input_sha256"], sha256_bytes(&fixture.input));
    assert_eq!(
        manifest["plants"][0]["value_sha256"],
        sha256_bytes(&fixture.plants[0].value)
    );
    assert!(
        verification::verify_bytes(&fixture.input, &manifest)
            .unwrap_err()
            .contains("seed recipe")
    );

    let mut fixture = dense(32768, Density::Positive, false, true);
    let start = fixture.plants[0].span.start;
    let replacement = if fixture.input[start + 4] == b'Z' {
        b'Y'
    } else {
        b'Z'
    };
    fixture.input[start + 4] = replacement;
    fixture.plants[0].value[4] = replacement;
    fixture.validate_construction().unwrap();
    assert!(
        verification::verify_bytes(&fixture.input, &fixture.manifest())
            .unwrap_err()
            .contains("seed")
    );

    let mut fixture = decoded(16, 2, false, true);
    let start = fixture.plants[0].span.start;
    let replacement = if fixture.layers[0][start + 4] == b'Z' {
        b'Y'
    } else {
        b'Z'
    };
    fixture.layers[0][start + 4] = replacement;
    fixture.plants[0].value[4] = replacement;
    fixture.layers[1] = STANDARD.encode(&fixture.layers[0]).into_bytes();
    let outer = fixture.outer.clone().unwrap();
    fixture.input[outer].copy_from_slice(STANDARD.encode(&fixture.layers[1]).as_bytes());
    fixture.validate_construction().unwrap();
    assert!(
        verification::verify_bytes(&fixture.input, &fixture.manifest())
            .unwrap_err()
            .contains("seed")
    );
}

#[test]
fn independent_seed_stream_matches_declared_domains_and_pair_gate_rejects_nonseparator_drift() {
    for (family, ordinal, length) in [
        ("boundary", 409_620, 36),
        ("density", 15, 36),
        ("single-carrier", 16, 36),
        ("connection-password", 27, 24),
    ] {
        assert_eq!(
            verification_seed::value(family, ordinal, length),
            seeded_value(family, ordinal, length)
        );
    }
    assert!(verification_seed::value("empty-control", 0, 0).is_empty());
    let lf = dense(32768, Density::Alternating, false, true);
    let space = dense(32768, Density::Alternating, false, false);
    let specs = verification_domain::required_cases("density").unwrap();
    let mut pairs = verification::PairReceipts::new();
    verification::record_pair(&mut pairs, specs[&lf.id], &lf.input).unwrap();
    assert!(verification::verify_pairs(&pairs).is_err());
    verification::record_pair(&mut pairs, specs[&space.id], &space.input).unwrap();
    verification::verify_pairs(&pairs).unwrap();

    let mut changed = space.input.clone();
    changed[14] = if changed[14] == b'Z' { b'Y' } else { b'Z' };
    let mut pairs = verification::PairReceipts::new();
    verification::record_pair(&mut pairs, specs[&lf.id], &lf.input).unwrap();
    verification::record_pair(&mut pairs, specs[&space.id], &changed).unwrap();
    assert!(verification::verify_pairs(&pairs).is_err());
}

#[test]
fn verifier_rejects_self_consistent_missing_empty_unknown_and_subset_family_inventories() {
    let valid = density_inventory_control();
    assert_eq!(verification::verify_inventory(&valid).unwrap().len(), 48);
    let mut missing = valid.clone();
    assert!(missing["cases"].as_array_mut().unwrap().pop().is_some());
    missing["logical_case_count"] = json!(47);
    missing["distinct_input_count"] = json!(47);
    assert!(verification::verify_inventory(&missing).is_err());
    let mut empty = valid.clone();
    empty["cases"] = json!([]);
    empty["logical_case_count"] = json!(0);
    empty["distinct_input_count"] = json!(0);
    assert!(verification::verify_inventory(&empty).is_err());
    for (field, value) in [
        ("family", json!("undeclared")),
        ("domain", json!("subset")),
        ("partition", json!("withheld")),
        ("development_seed", json!("different")),
        ("seed_recipe", json!("different")),
    ] {
        let mut wrong = valid.clone();
        wrong[field] = value;
        assert!(verification::verify_inventory(&wrong).is_err(), "{field}");
    }
    let mut collapsed_input = valid;
    collapsed_input["cases"][1]["input_sha256"] =
        collapsed_input["cases"][0]["input_sha256"].clone();
    assert!(verification::verify_inventory(&collapsed_input).is_err());
}

#[test]
fn independent_domain_counts_logical_cases_distinct_inputs_and_schedule_expectations_separately() {
    for (family, logical, distinct, schedules) in [
        ("boundaries", 1908, 1908, 0),
        ("density", 48, 48, 0),
        ("decoded-carrier", 32, 28, 0),
        ("connections", 36, 30, 0),
        ("partitions", 2, 2, 16),
    ] {
        assert_eq!(
            verification_domain::required_cases(family).unwrap().len(),
            logical
        );
        assert_eq!(
            verification_domain::counts(family).unwrap(),
            (logical, distinct, schedules)
        );
    }
    let boundaries = verification_domain::required_cases("boundaries").unwrap();
    assert!(boundaries.contains_key("boundary-base64-182344-54-positive-no-lf"));
    assert!(boundaries.contains_key("boundary-base64-182344-55-positive-no-lf"));
    assert!(boundaries.contains_key("boundary-raw-4096-40-internal-negative-no-lf"));
}

#[test]
fn forty_one_byte_carrier_containing_valid_substring_is_not_a_negative() {
    let mut input = pat("negative-trap", 0);
    input.push(b'Z');
    let fixture = Fixture::plain("invalid-negative".into(), "test", input);
    assert!(fixture.validate_construction().is_err());
}

#[test]
fn dense_pairs_preserve_geometry_and_exact_occurrence_multiplicity() {
    for density in [Density::Positive, Density::Alternating, Density::Negative] {
        let unique = dense(64 * 16, density, false, true);
        let repeated = dense(64 * 16, density, true, true);
        let flat = dense(64 * 16, density, false, false);
        for fixture in [&unique, &repeated, &flat] {
            fixture.validate_construction().unwrap();
            assert_eq!(fixture.input.len(), 64 * 16);
        }
        assert_eq!(
            unique.plants.iter().map(|p| &p.span).collect::<Vec<_>>(),
            repeated.plants.iter().map(|p| &p.span).collect::<Vec<_>>()
        );
        assert_eq!(unique.plants, flat.plants);
        for (offset, (left, right)) in unique.input.iter().zip(&flat.input).enumerate() {
            if offset % 64 == 63 {
                assert_eq!((*left, *right), (b'\n', b' '));
            } else {
                assert_eq!(left, right);
            }
        }
        assert_eq!(
            unique.plants.len(),
            match density {
                Density::Positive => 16,
                Density::Alternating => 8,
                Density::Negative => 0,
            }
        );
        assert_eq!(
            unique
                .plants
                .iter()
                .map(|p| &p.value)
                .collect::<BTreeSet<_>>()
                .len(),
            unique.plants.len()
        );
        assert!(
            repeated
                .plants
                .iter()
                .map(|p| &p.value)
                .collect::<BTreeSet<_>>()
                .len()
                <= 1
        );
    }
}

#[test]
fn many_decoded_values_share_one_outer_span_without_collapsing_occurrences() {
    for depth in [1, 2] {
        for repeated in [false, true] {
            let fixture = decoded(16, depth, repeated, true);
            fixture.validate_construction().unwrap();
            assert_eq!(fixture.plants.len(), 16);
            let mut decoded_bytes = fixture.input[fixture.outer.clone().unwrap()].to_vec();
            for _ in 0..depth {
                decoded_bytes = STANDARD.decode(decoded_bytes).unwrap();
            }
            assert_eq!(decoded_bytes, fixture.plaintext());
            let manifest = fixture.manifest();
            let outer = &manifest["plants"][0]["physical_source_carrier_bytes"];
            assert!(
                manifest["plants"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|plant| &plant["physical_source_carrier_bytes"] == outer)
            );
            assert_eq!(
                manifest["expected_unique_values"],
                if repeated { 1 } else { 16 }
            );
            decoded(16, depth, repeated, false)
                .validate_construction()
                .unwrap();
        }
    }
}

#[test]
fn report_growth_caps_are_construction_only_and_keep_large_cases_visible() {
    assert!(dense(32768, Density::Positive, false, false).timing_eligible);
    assert!(!dense(131_072, Density::Positive, false, false).timing_eligible);
    assert!(dense(131_072, Density::Positive, false, true).timing_eligible);
    assert!(decoded(256, 2, false, true).timing_eligible);
    assert!(!decoded(4096, 2, false, true).timing_eligible);
}

#[test]
fn reader_partitions_cover_each_byte_once_and_preserve_boundary_tokens() {
    for encoded in [false, true] {
        let fixture = boundary(
            4096,
            if encoded { 55 } else { 20 },
            encoded,
            Mutation::Positive,
            Layout::NoLf,
        );
        for schedule in [&[1][..], &[2], &[7], &[4096], &[1, 3, 2, 7, 31, 64, 5]] {
            let ranges = partition(fixture.input.len(), schedule);
            assert_eq!(ranges.first().unwrap().start, 0);
            assert_eq!(ranges.last().unwrap().end, fixture.input.len());
            assert!(ranges.windows(2).all(|pair| pair[0].end == pair[1].start));
            let reconstructed = ranges
                .into_iter()
                .flat_map(|range| fixture.input[range].to_vec())
                .collect::<Vec<_>>();
            assert_eq!(reconstructed, fixture.input);
        }
    }
    assert!(partition(0, &[1, 7]).is_empty());
}

#[test]
fn connection_spans_are_literal_and_policy_decisions_are_not_fabricated() {
    let mut count = 0;
    connections::generate(&mut |fixture| {
        fixture.validate_construction()?;
        let manifest = fixture.manifest();
        assert_eq!(
            manifest["result_requirement"],
            "policy-review-required-before-scoring"
        );
        assert!(!fixture.timing_eligible);
        assert!(manifest["expected_occurrences"].is_null());
        for plant in &fixture.plants {
            assert_eq!(&fixture.input[plant.span.clone()], plant.value);
            assert_eq!(plant.carrier.start, 0);
            assert_eq!(plant.carrier.end + 1, fixture.input.len());
        }
        count += 1;
        Ok(())
    })
    .unwrap();
    assert_eq!(count, 36);
}

#[test]
fn connection_percent_semantics_distinguish_uri_encoding_from_literal_property_bytes() {
    for (form, ordinal, syntax, differs) in [
        ("uri-userinfo", 1, "uri-percent-encoded", true),
        ("jdbc-query", 10, "uri-percent-encoded", true),
        ("odbc-properties", 19, "literal-percent-containing", false),
        ("libpq-keyword", 28, "literal-percent-containing", false),
    ] {
        let fixture = connections::connection(form, "percent-encoded", ordinal);
        let manifest = fixture.manifest();
        verification::verify_bytes(&fixture.input, &manifest).unwrap();
        let source = &fixture.plants[0].value;
        let recipe = verification_seed::connection_password(form, "percent-encoded").unwrap();
        assert_eq!(source.len(), 26);
        assert_eq!(source[0], b'%');
        assert_eq!(manifest["details"]["value_syntax"], syntax);
        assert_eq!(
            manifest["details"]["wire_value_differs_from_semantic_password"],
            differs
        );
        assert_eq!(
            manifest["details"]["generated_password_sha256"],
            sha256_bytes(&recipe)
        );
        assert_eq!(
            manifest["details"]["source_password_sha256"],
            sha256_bytes(source)
        );
        let semantic = if differs {
            recipe.as_slice()
        } else {
            source.as_slice()
        };
        assert_eq!(
            manifest["details"]["semantic_password_sha256"],
            sha256_bytes(semantic)
        );
        assert_eq!(
            manifest["details"]["source_password_sha256"]
                != manifest["details"]["semantic_password_sha256"],
            differs
        );
        assert_eq!(
            &fixture.input[fixture.plants[0].span.clone()],
            source.as_slice()
        );

        let mut wrong_flag = manifest.clone();
        wrong_flag["details"]["wire_value_differs_from_semantic_password"] = json!(!differs);
        assert!(verification::verify_bytes(&fixture.input, &wrong_flag).is_err());
        let mut wrong_semantics = manifest.clone();
        wrong_semantics["details"]["semantic_password_sha256"] = json!(sha256_bytes(if differs {
            source.as_slice()
        } else {
            recipe.as_slice()
        }));
        assert!(verification::verify_bytes(&fixture.input, &wrong_semantics).is_err());
        let mut wrong_syntax = manifest.clone();
        wrong_syntax["details"]["value_syntax"] = json!(if differs {
            "literal-percent-containing"
        } else {
            "uri-percent-encoded"
        });
        assert!(verification::verify_bytes(&fixture.input, &wrong_syntax).is_err());
    }
}

#[test]
fn connection_negatives_have_no_password_semantics_and_preserve_malformed_literal_evidence() {
    connections::generate(&mut |fixture| {
        let manifest = fixture.manifest();
        verification::verify_bytes(&fixture.input, &manifest)?;
        let details = &manifest["details"];
        let form = details["form"].as_str().unwrap();
        let class = details["class"].as_str().unwrap();
        let recipe = verification_seed::connection_password(form, class)?;
        assert_eq!(details["generated_password_bytes"], 24);
        assert_eq!(details["generated_password_sha256"], sha256_bytes(&recipe));
        assert!(details.get("password_sha256").is_none());
        assert!(details.get("literal_password_bytes").is_none());
        if class == "literal" {
            assert_eq!(details["value_syntax"], "literal");
            assert_eq!(details["wire_value_differs_from_semantic_password"], false);
            assert_eq!(
                details["source_password_sha256"],
                details["semantic_password_sha256"]
            );
            assert_eq!(
                details["semantic_password_sha256"],
                details["generated_password_sha256"]
            );
        } else if class != "percent-encoded" {
            assert!(fixture.plants.is_empty());
            for name in [
                "value_syntax",
                "wire_value_differs_from_semantic_password",
                "source_password_sha256",
                "semantic_password_sha256",
            ] {
                assert_eq!(details.get(name), Some(&Value::Null));
                let mut missing = manifest.clone();
                assert!(
                    missing["details"]
                        .as_object_mut()
                        .unwrap()
                        .remove(name)
                        .is_some()
                );
                assert!(
                    verification::verify_bytes(&fixture.input, &missing).is_err(),
                    "{form}/{class}/{name}"
                );
            }
            for name in ["source_password_sha256", "semantic_password_sha256"] {
                let mut false_password = manifest.clone();
                false_password["details"][name] = json!(sha256_bytes(&recipe));
                assert!(verification::verify_bytes(&fixture.input, &false_password).is_err());
            }
        }
        if class == "malformed-delimiter" {
            let retained = &details["retained_literal"];
            let span = verification::range(&retained["source_bytes"], fixture.input.len())?;
            assert_eq!(&fixture.input[span], recipe.as_slice());
            assert_eq!(retained["value_sha256"], sha256_bytes(&recipe));
            assert_eq!(
                retained["role"],
                "generated-literal-outside-declared-password-slot"
            );
            let mut false_slot = manifest.clone();
            false_slot["details"]["retained_literal"]["role"] = json!("structural-password");
            assert!(verification::verify_bytes(&fixture.input, &false_slot).is_err());
        } else {
            assert_eq!(details.get("retained_literal"), Some(&Value::Null));
        }
        let mut obsolete = manifest.clone();
        obsolete["details"]["password_sha256"] = json!(sha256_bytes(&recipe));
        assert!(verification::verify_bytes(&fixture.input, &obsolete).is_err());
        Ok(())
    })
    .unwrap();
}

#[test]
fn paths_require_new_absolute_explicit_family() {
    for arguments in [
        vec![],
        vec!["--family", "density", "--output", "relative"],
        vec!["--family", "unknown", "--output", "/private/tmp/new"],
        vec![
            "--family",
            "density",
            "--family",
            "density",
            "--output",
            "/private/tmp/new",
        ],
    ] {
        assert!(
            Request::parse(&arguments.into_iter().map(str::to_owned).collect::<Vec<_>>()).is_err()
        );
    }
}
