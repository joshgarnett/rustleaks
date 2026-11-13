//! Bind mutable Windows runtime providers to the actual native link action.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};

use super::{notices, sha256_file, target_config, write_json};
use crate::tooling::command_output;

const PER_CRATE: &str = "--@rules_rust//rust/settings:experimental_per_crate_rustc_flag=crates/rustleaks-cli/src/main.rs@";
const KIND: &str = "native-toolset-runtime-and-official-terms";
const MAP_NAME: &str = "rustleaks-runtime.map";

#[allow(clippy::too_many_arguments, clippy::too_many_lines)] // Bind the exact candidate, configured action and native linker outputs in one transaction.
pub(super) fn collect(
    root: &Path,
    output_root: &Path,
    target: &str,
    commit: &str,
    binary_sha256: &str,
    bundle: &notices::Bundle,
    map: &Path,
    trace: &Path,
) -> Result<Value, String> {
    if std::env::consts::OS != "windows" {
        return Err("Windows runtime evidence requires a Windows host".into());
    }
    let component = microsoft_component(bundle)?;
    let config = target_config(target)?;
    let flags = windows_flags(config);
    let mut query = bazel_command(root, output_root);
    query.arg("aquery").args(&flags).args([
        "--output=jsonproto",
        "mnemonic(\"Rustc\", //crates/rustleaks-cli:rustleaks)",
    ]);
    let query = command_output(&mut query)?;
    if query.len() > 16 * 1024 * 1024 {
        return Err("selected native action evidence exceeds its size limit".into());
    }
    let query: Value = serde_json::from_str(&query).map_err(|error| error.to_string())?;
    let action = cli_action(&query, target)?;
    let mut info = bazel_command(root, output_root);
    info.arg("info").args(&flags).arg("execution_root");
    let execution_root = PathBuf::from(command_output(&mut info)?.trim());
    if fs::canonicalize(map)
        .map_err(|error| format!("selected CLI map output is unavailable: {error}"))?
        != fs::canonicalize(execution_root.join(MAP_NAME))
            .map_err(|error| format!("configured CLI map output is unavailable: {error}"))?
    {
        return Err("native map is not the configured CLI action's execution-root output".into());
    }
    let arguments = strings(&action["arguments"])?;
    let output = one_argument(&arguments, "--emit=link=")?;
    notices::portable_path(output)?;
    if !output.starts_with("bazel-out/") || !output.ends_with("/crates/rustleaks-cli/rustleaks.exe")
    {
        return Err("selected CLI action has an unexpected binary output path".into());
    }
    if sha256_file(&execution_root.join(output))? != binary_sha256 {
        return Err(
            "selected Bazel CLI action output does not match the binary being packaged".into(),
        );
    }
    let evidence_root = trace
        .parent()
        .ok_or("native trace has no evidence directory")?;
    write_json(
        &evidence_root.join("selected-action.json"),
        &json!({"target":target,"candidate":commit,"binary_sha256":binary_sha256,"mnemonic":action["mnemonic"],"arguments":action["arguments"]}),
    )?;
    let linker = codegen_values(&arguments, "linker")?;
    let [linker] = linker.as_slice() else {
        return Err("selected CLI action must name exactly one linker".into());
    };
    let linker = fs::canonicalize(linker)
        .map_err(|error| format!("cannot inspect selected linker: {error}"))?;
    let linker_path = normalized_path(&linker.to_string_lossy());
    let (provider_root, _) = linker_path
        .split_once("/vc/tools/msvc/")
        .ok_or("selected linker is not an identified MSVC provider")?;
    let edition = string(&component["source"], "visual_studio_edition")?.to_ascii_lowercase();
    let studio_major = string(&component["source"], "visual_studio_version")?
        .split('.')
        .next()
        .ok_or("reviewed Visual Studio version is missing")?;
    if !provider_root.ends_with(&format!(
        "/microsoft visual studio/{studio_major}/{edition}"
    )) {
        return Err(
            "selected Visual Studio provider differs from the reviewed edition and major version"
                .into(),
        );
    }
    let expected_linker = &component["source"]["target_linker_files"][target];
    let actual_linker = observe_file(&linker, provider_root, expected_linker)?;
    let map_text = read_text(map, 32 * 1024 * 1024)?;
    let trace_text = read_text(trace, 64 * 1024 * 1024)?;
    let mut image_header = Vec::new();
    fs::File::open(execution_root.join(output))
        .map_err(|error| error.to_string())?
        .take(1024 * 1024)
        .read_to_end(&mut image_header)
        .map_err(|error| error.to_string())?;
    let map_identity = map_binary_identity(&image_header, &map_text, target)?;
    let members = map_members(&map_text)?;
    let searches = searched_paths(&trace_text)?;
    let expected_inputs = component["source"]["target_input_files"][target]
        .as_array()
        .ok_or("reviewed runtime omits target input files")?;
    let expected = expected_inputs
        .iter()
        .map(|record| Ok((library_id(string(record, "original_path")?)?, record)))
        .collect::<Result<BTreeMap<_, _>, String>>()?;
    if expected.len() != expected_inputs.len() {
        return Err("reviewed native inputs have ambiguous library identities".into());
    }
    let mut observed = BTreeMap::new();
    for (library, selected_members) in &members {
        let candidates = searches
            .get(library)
            .ok_or_else(|| format!("native map library {library} has no observed search path"))?;
        let mut resolved = BTreeMap::new();
        for candidate in candidates {
            let candidate = Path::new(candidate);
            let candidate = if candidate.is_absolute() {
                candidate.to_path_buf()
            } else {
                execution_root.join(candidate)
            };
            let canonical = fs::canonicalize(&candidate).map_err(|error| {
                format!(
                    "observed library path {} is unavailable: {error}",
                    candidate.display()
                )
            })?;
            resolved.insert(normalized_path(&canonical.to_string_lossy()), canonical);
        }
        let (identity, path) = unique_provider(resolved, library)?;
        if identity.ends_with(".rlib") {
            continue;
        }
        if !identity.ends_with(".lib") {
            return Err(format!("unreviewed native provider type for {library}"));
        }
        let expected = expected.get(library).ok_or_else(|| {
            format!("selected native runtime library {library} has no reviewed provider")
        })?;
        let mut record = observe_file(&path, provider_root, expected)?;
        record["members"] = json!(selected_members);
        observed.insert(library.clone(), record);
    }
    if observed.keys().ne(expected.keys()) {
        return Err(
            "actual native library coverage differs from the reviewed target inputs".into(),
        );
    }
    let evidence = json!({
        "schema_version":1,"target":target,"candidate":commit,"binary_sha256":binary_sha256,
        "component_id":component["id"],"selection":"configured-cli-action-and-native-map-search-trace",
        "map_identity":map_identity,"linker":actual_linker,"inputs":observed.into_values().collect::<Vec<_>>(),
    });
    validate(bundle, &evidence, target, commit, binary_sha256)?;
    write_json(&evidence_root.join("verified-runtime.json"), &evidence)?;
    Ok(evidence)
}

fn bazel_command(root: &Path, output_root: &Path) -> Command {
    let mut command = Command::new("bazelisk");
    command
        .current_dir(root)
        .arg(format!("--output_user_root={}", output_root.display()))
        .arg("--windows_enable_symlinks");
    command
}

fn windows_flags(config: &str) -> Vec<String> {
    vec![
        format!("--config={config}"),
        "--repo_env=BAZEL_DO_NOT_DETECT_CPP_TOOLCHAIN=0".into(),
        "--extra_toolchains=@@rules_cc++cc_configure_extension+local_config_cc_toolchains//:all"
            .into(),
        format!("{PER_CRATE}-Wlinker-messages"),
        format!("{PER_CRATE}-Clink-arg=/VERBOSE:LIB"),
        format!("{PER_CRATE}-Clink-arg=/MAP:{MAP_NAME}"),
    ]
}

fn cli_action<'a>(query: &'a Value, target: &str) -> Result<&'a Value, String> {
    let target_argument = format!("--target={target}");
    let selected = query["actions"]
        .as_array()
        .ok_or("native aquery omits actions")?
        .iter()
        .filter(|action| {
            action["mnemonic"] == "Rustc"
                && action["arguments"].as_array().is_some_and(|args| {
                    args.iter().any(|arg| arg == "--crate-type=bin")
                        && args.iter().any(|arg| arg == "--crate-name=rustleaks")
                        && args
                            .iter()
                            .any(|arg| arg.as_str() == Some(target_argument.as_str()))
                })
        })
        .collect::<Vec<_>>();
    let [action] = selected.as_slice() else {
        return Err("native aquery must contain exactly one selected CLI binary action".into());
    };
    if !query["targets"].as_array().is_some_and(|targets| {
        targets.iter().any(|entry| {
            entry["id"] == action["targetId"]
                && entry["label"] == "//crates/rustleaks-cli:rustleaks"
        })
    }) {
        return Err("native Rustc action does not belong to the CLI binary target".into());
    }
    let arguments = strings(&action["arguments"])?;
    let link_args = codegen_values(&arguments, "link-arg")?;
    if !arguments.contains(&"-Wlinker-messages")
        || !link_args
            .iter()
            .any(|arg| arg.eq_ignore_ascii_case("/VERBOSE:LIB"))
    {
        return Err("selected CLI action omits native linker trace diagnostics".into());
    }
    let maps = link_args
        .iter()
        .filter_map(|arg| arg.strip_prefix("/MAP:"))
        .collect::<Vec<_>>();
    if maps != [MAP_NAME] {
        return Err("native map does not match the selected CLI action's map output".into());
    }
    Ok(action)
}

fn codegen_values(arguments: &[&str], name: &str) -> Result<Vec<String>, String> {
    let mut result = Vec::new();
    let mut position = 0;
    while position < arguments.len() {
        let argument = arguments[position];
        let value = if argument == "-C" || argument == "--codegen" {
            position += 1;
            Some(
                *arguments
                    .get(position)
                    .ok_or("selected action has a truncated codegen option")?,
            )
        } else {
            argument
                .strip_prefix("--codegen=")
                .or_else(|| argument.strip_prefix("-C"))
        };
        if let Some(value) = value.and_then(|value| value.strip_prefix(&format!("{name}="))) {
            result.push(value.to_owned());
        }
        position += 1;
    }
    Ok(result)
}

fn one_argument<'a>(arguments: &[&'a str], prefix: &str) -> Result<&'a str, String> {
    let values = arguments
        .iter()
        .filter_map(|argument| argument.strip_prefix(prefix))
        .collect::<Vec<_>>();
    match values.as_slice() {
        [value] => Ok(value),
        _ => Err(format!(
            "selected action must contain exactly one {prefix} option"
        )),
    }
}

fn searched_paths(trace: &str) -> Result<BTreeMap<String, BTreeSet<String>>, String> {
    let mut searches = BTreeMap::<String, BTreeSet<String>>::new();
    for line in trace.lines() {
        let line = line.trim().trim_end_matches('\u{240d}').trim();
        let Some(path) = line
            .strip_prefix("Searching ")
            .and_then(|line| line.strip_suffix(':'))
        else {
            continue;
        };
        if !path.to_ascii_lowercase().ends_with(".lib")
            && !path.to_ascii_lowercase().ends_with(".rlib")
        {
            continue;
        }
        searches
            .entry(library_id(path)?)
            .or_default()
            .insert(path.to_owned());
    }
    if searches.is_empty() {
        return Err("native linker trace contains no observed library search paths".into());
    }
    Ok(searches)
}

fn map_members(map: &str) -> Result<BTreeMap<String, BTreeSet<String>>, String> {
    let mut members = BTreeMap::<String, BTreeSet<String>>::new();
    for line in map.lines() {
        let columns = line.split_ascii_whitespace().collect::<Vec<_>>();
        let Some(address) = columns.first() else {
            continue;
        };
        let Some((section, offset)) = address.split_once(':') else {
            continue;
        };
        if section.len() != 4
            || offset.len() < 8
            || !section
                .bytes()
                .chain(offset.bytes())
                .all(|byte| byte.is_ascii_hexdigit())
        {
            continue;
        }
        if columns.len() < 4
            || columns[2].len() != 16
            || !columns[2].bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            continue;
        }
        let Some(last) = columns.last() else {
            continue;
        };
        if let Some((library, member)) = last.split_once(':') {
            if library.is_empty()
                || library.contains(['/', '\\'])
                || member.is_empty()
                || member.contains(['/', '\\', ':'])
                || member.len() > 255
            {
                return Err("native map has an unsupported library/member identity".into());
            }
            members
                .entry(library.to_ascii_lowercase())
                .or_default()
                .insert((*member).to_owned());
        } else if !last.ends_with(".rcgu.o")
            && !matches!(*last, "<absolute>" | "<linker-defined>" | "<common>")
        {
            return Err(format!(
                "native map contains an unreviewed direct object {last}"
            ));
        }
    }
    if members.is_empty() {
        return Err("native map contains no library/member associations".into());
    }
    Ok(members)
}

fn map_binary_identity(header: &[u8], map: &str, target: &str) -> Result<Value, String> {
    let pe = usize::try_from(u32_at(header, 0x3c)?).map_err(|error| error.to_string())?;
    if header.get(..2) != Some(b"MZ") || pe > 65536 || header.get(pe..pe + 4) != Some(b"PE\0\0") {
        return Err("native executable has no bounded PE header".into());
    }
    let machine = u16_at(header, pe + 4)?;
    let expected_machine = windows_machine(target)?;
    let sections = usize::from(u16_at(header, pe + 6)?);
    let timestamp = u32_at(header, pe + 8)?;
    let optional_size = usize::from(u16_at(header, pe + 20)?);
    let optional = pe + 24;
    if machine != expected_machine
        || sections == 0
        || sections > 96
        || u16_at(header, optional)? != 0x20b
        || optional_size < 32
    {
        return Err(
            "native PE target or optional header differs from the selected Windows target".into(),
        );
    }
    let entry_rva = u32_at(header, optional + 16)?;
    let image_base = u64::from_le_bytes(
        header
            .get(optional + 24..optional + 32)
            .ok_or("truncated PE image base")?
            .try_into()
            .map_err(|_| "truncated PE image base")?,
    );
    let map_timestamp = u32::from_str_radix(map_value(map, "Timestamp is ")?, 16)
        .map_err(|_| "native map has an invalid reproducible image hash")?;
    let map_base = u64::from_str_radix(map_value(map, "Preferred load address is ")?, 16)
        .map_err(|_| "native map has an invalid image base")?;
    let (section, offset) = map_value(map, "entry point at ")?
        .split_once(':')
        .ok_or("native map entry point is missing")?;
    let section =
        usize::from(u16::from_str_radix(section, 16).map_err(|_| "invalid map entry section")?);
    let offset = u32::from_str_radix(offset, 16).map_err(|_| "invalid map entry offset")?;
    if section == 0 || section > sections {
        return Err("native map entry section is outside the selected binary".into());
    }
    let section_rva = u32_at(header, optional + optional_size + (section - 1) * 40 + 12)?;
    if timestamp != map_timestamp
        || image_base != map_base
        || section_rva.checked_add(offset) != Some(entry_rva)
    {
        return Err("native linker map does not match the selected binary's reproducible hash, base, and entry point".into());
    }
    Ok(
        json!({"machine":machine,"timestamp":timestamp,"image_base":image_base,"entry_rva":entry_rva}),
    )
}

fn windows_machine(target: &str) -> Result<u16, String> {
    match target {
        "x86_64-pc-windows-msvc" => Ok(0x8664),
        "aarch64-pc-windows-msvc" => Ok(0xaa64),
        _ => Err("runtime evidence target must be one of the two Windows MSVC targets".into()),
    }
}

fn map_value<'a>(map: &'a str, prefix: &str) -> Result<&'a str, String> {
    let values = map
        .lines()
        .filter_map(|line| {
            line.trim()
                .strip_prefix(prefix)
                .and_then(|value| value.split_ascii_whitespace().next())
        })
        .collect::<Vec<_>>();
    match values.as_slice() {
        [value] => Ok(value),
        _ => Err(format!(
            "native map must contain exactly one {prefix} identity"
        )),
    }
}

fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, String> {
    Ok(u16::from_le_bytes(
        bytes
            .get(offset..offset + 2)
            .ok_or("truncated PE field")?
            .try_into()
            .map_err(|_| "truncated PE field")?,
    ))
}
fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, String> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or("truncated PE field")?
            .try_into()
            .map_err(|_| "truncated PE field")?,
    ))
}

fn library_id(path: &str) -> Result<String, String> {
    let name = path
        .rsplit(['/', '\\'])
        .next()
        .ok_or("native library has no filename")?
        .to_ascii_lowercase();
    name.strip_suffix(".rlib")
        .or_else(|| name.strip_suffix(".lib"))
        .map(str::to_owned)
        .ok_or_else(|| format!("unsupported native library filename {name}"))
}

fn unique_provider(
    providers: BTreeMap<String, PathBuf>,
    library: &str,
) -> Result<(String, PathBuf), String> {
    if providers.len() != 1 {
        return Err(format!(
            "native map library {library} has ambiguous or missing actual providers"
        ));
    }
    providers
        .into_iter()
        .next()
        .ok_or_else(|| "native provider disappeared".into())
}

fn observe_file(path: &Path, provider_root: &str, expected: &Value) -> Result<Value, String> {
    let actual = normalized_path(&path.to_string_lossy());
    let expected_path = normalized_path(string(expected, "original_path")?);
    let original = provider_relative_path(&actual, provider_root)?;
    if original != expected_path {
        return Err(format!(
            "selected native provider path differs from reviewed identity {}",
            string(expected, "original_path")?
        ));
    }
    let size = fs::metadata(path).map_err(|error| error.to_string())?.len();
    if expected["size"].as_u64() != Some(size) {
        return Err(format!(
            "selected native file {original} has unreviewed size {size}"
        ));
    }
    validate_file_identity(expected, &original, &sha256_file(path)?, size)?;
    Ok(expected.clone())
}

fn provider_relative_path(actual: &str, provider_root: &str) -> Result<String, String> {
    if actual.starts_with(&format!("{provider_root}/vc/tools/msvc/")) {
        return Ok(actual[provider_root.len() + 1..].to_owned());
    }
    if actual.contains("/vc/tools/msvc/") {
        return Err("selected native library comes from a different MSVC installation than the configured linker".into());
    }
    let (_, suffix) = actual
        .split_once("/windows kits/10/")
        .ok_or("selected native input is outside the identified MSVC and Windows SDK providers")?;
    Ok(format!("windows kits/10/{suffix}"))
}

fn validate_file_identity(
    expected: &Value,
    original_path: &str,
    digest: &str,
    size: u64,
) -> Result<(), String> {
    if normalized_path(string(expected, "original_path")?) != normalized_path(original_path)
        || expected["sha256"] != digest
        || expected["size"].as_u64() != Some(size)
    {
        return Err(format!(
            "actual selected native file {original_path} has SHA-256 {digest} and size {size}, differing from its reviewed identity"
        ));
    }
    Ok(())
}

fn normalized_path(path: &str) -> String {
    path.trim_start_matches("\\\\?\\")
        .replace('\\', "/")
        .split('/')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("/")
        .to_ascii_lowercase()
}

pub(super) fn validate(
    bundle: &notices::Bundle,
    evidence: &Value,
    target: &str,
    commit: &str,
    binary_sha256: &str,
) -> Result<(), String> {
    let component = microsoft_component(bundle)?;
    let source = &component["source"];
    let linker = &source["target_linker_files"][target];
    if !string(linker, "original_path")?.starts_with(&format!(
        "VC/Tools/MSVC/{}/",
        string(source, "toolset_version")?
    )) || linker["file_version"] != source["linker_file_version"]
    {
        return Err("reviewed native linker pin disagrees with the toolset identity".into());
    }
    let expected_inputs = component["source"]["target_input_files"][target]
        .as_array()
        .ok_or("reviewed runtime omits target input identities")?;
    let inputs = evidence["inputs"]
        .as_array()
        .ok_or("native runtime evidence omits observed inputs")?;
    if inputs.len() != expected_inputs.len() {
        return Err("native runtime evidence has incomplete or extra provider coverage".into());
    }
    let mut seen = BTreeSet::new();
    let mut canonical = BTreeMap::new();
    for input in inputs {
        let path = string(input, "original_path")?;
        if !seen.insert(path) {
            return Err("native runtime evidence repeats a provider input".into());
        }
        let expected = expected_inputs
            .iter()
            .find(|expected| expected["original_path"] == path)
            .ok_or("native runtime evidence contains an unreviewed provider input")?;
        let members = input["members"]
            .as_array()
            .ok_or("native runtime evidence omits mapped members")?;
        let mut sorted = BTreeSet::new();
        for member in members {
            let member = member
                .as_str()
                .ok_or("native runtime member is not a string")?;
            if member.is_empty()
                || member.len() > 255
                || member.contains(['/', '\\', ':'])
                || !sorted.insert(member)
            {
                return Err("native runtime member identity is unsafe or repeated".into());
            }
        }
        if sorted.is_empty() {
            return Err("native runtime provider has no actual mapped members".into());
        }
        let mut expected = expected.clone();
        expected["members"] = json!(sorted);
        if *input != expected {
            return Err("native runtime evidence differs from reviewed provider bytes or canonical mapped members".into());
        }
        canonical.insert(library_id(path)?, expected);
    }
    let identity = &evidence["map_identity"];
    let expected_identity = json!({"machine":windows_machine(target)?,"timestamp":identity["timestamp"],"image_base":identity["image_base"],"entry_rva":identity["entry_rva"]});
    if identity != &expected_identity
        || identity["timestamp"]
            .as_u64()
            .is_none_or(|value| value > u64::from(u32::MAX))
        || identity["entry_rva"]
            .as_u64()
            .is_none_or(|value| value == 0 || value > u64::from(u32::MAX))
        || identity["image_base"].as_u64().is_none()
    {
        return Err("native runtime evidence has an invalid binary/map identity".into());
    }
    let expected = json!({"schema_version":1,"target":target,"candidate":commit,"binary_sha256":binary_sha256,"component_id":component["id"],"selection":"configured-cli-action-and-native-map-search-trace","map_identity":expected_identity,"linker":component["source"]["target_linker_files"][target],"inputs":canonical.into_values().collect::<Vec<_>>()});
    if evidence != &expected || evidence["linker"].is_null() {
        return Err("native runtime evidence does not match the reviewed linker, target, candidate, binary, and provider scope".into());
    }
    Ok(())
}

fn microsoft_component(bundle: &notices::Bundle) -> Result<&Value, String> {
    let selected = bundle.index["components"]
        .as_array()
        .ok_or("notice index omits components")?
        .iter()
        .filter(|component| component["source"]["kind"] == KIND)
        .collect::<Vec<_>>();
    match selected.as_slice() {
        [component] => Ok(component),
        _ => {
            Err("Windows release requires exactly one reviewed Microsoft runtime component".into())
        }
    }
}

fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value[key]
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("native runtime record omits {key}"))
}
fn strings(value: &Value) -> Result<Vec<&str>, String> {
    value
        .as_array()
        .ok_or("native action arguments are missing")?
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| "native action argument is not a string".into())
        })
        .collect()
}

fn read_text(path: &Path, limit: u64) -> Result<String, String> {
    let file = fs::File::open(path).map_err(|error| error.to_string())?;
    if !file
        .metadata()
        .map_err(|error| error.to_string())?
        .is_file()
        || file.metadata().map_err(|error| error.to_string())?.len() > limit
    {
        return Err("native linker evidence is not a bounded regular file".into());
    }
    let mut text = String::new();
    file.take(limit + 1)
        .read_to_string(&mut text)
        .map_err(|error| error.to_string())?;
    if text.len() as u64 > limit {
        return Err("native linker evidence exceeded its byte limit".into());
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TARGET: &str = "x86_64-pc-windows-msvc";

    fn action_fixture() -> Value {
        json!({"targets":[{"id":7,"label":"//crates/rustleaks-cli:rustleaks"}],"actions":[{"targetId":7,"mnemonic":"Rustc","arguments":["rustc.exe","--crate-name=rustleaks","--crate-type=bin",format!("--target={TARGET}"),"--emit=link=bazel-out/test/bin/crates/rustleaks-cli/rustleaks.exe","--codegen=linker=C:/Visual Studio/VC/Tools/MSVC/14.51.36231/bin/HostX64/x64/link.exe","-Wlinker-messages","-Clink-arg=/VERBOSE:LIB","-C","link-arg=/MAP:rustleaks-runtime.map"]}]})
    }

    #[test]
    fn configured_action_requires_exact_target_diagnostics_and_map_output() {
        let action = action_fixture();
        cli_action(&action, TARGET).unwrap();
        assert!(cli_action(&action, "aarch64-pc-windows-msvc").is_err());
        let mut duplicate = action.clone();
        duplicate["actions"]
            .as_array_mut()
            .unwrap()
            .push(action["actions"][0].clone());
        assert!(cli_action(&duplicate, TARGET).is_err());
        for omitted in ["-Wlinker-messages", "-Clink-arg=/VERBOSE:LIB"] {
            let mut missing = action.clone();
            missing["actions"][0]["arguments"]
                .as_array_mut()
                .unwrap()
                .retain(|arg| arg != omitted);
            assert!(cli_action(&missing, TARGET).is_err());
        }
        let mut stale = action.clone();
        *stale["actions"][0]["arguments"]
            .as_array_mut()
            .unwrap()
            .last_mut()
            .unwrap() = json!("link-arg=/MAP:stale.map");
        assert!(cli_action(&stale, TARGET).is_err());
        let mut foreign = action;
        foreign["targets"][0]["label"] = json!("//other:binary");
        assert!(cli_action(&foreign, TARGET).is_err());
        assert_eq!(
            codegen_values(
                &[
                    "-Clinker=one",
                    "--codegen",
                    "linker=two",
                    "--codegen=linker=three"
                ],
                "linker"
            )
            .unwrap(),
            ["one", "two", "three"]
        );
        assert!(codegen_values(&["-C"], "linker").is_err());
    }

    #[test]
    fn map_and_search_records_preserve_native_provider_identity() {
        let map = " Start Length Name Class\n 0001:00000000 00001000H .text CODE\n 0001:00000200 mainCRTStartup 0000000140001200 f msvcrt:exe_main.obj\n 0002:00000020 guard 0000000140002020 vcruntime:softmemtag.obj\n 0000:00000000 __ImageBase 0000000140000000 <absolute>\n";
        let members = map_members(map).unwrap();
        assert_eq!(members["msvcrt"], BTreeSet::from(["exe_main.obj".into()]));
        assert_eq!(members.len(), 2);
        let searches = searched_paths("warning: linker stdout: \u{240d}\n    Searching C:\\VC\\msvcrt.lib:\u{240d}\n    Searching C:\\SDK\\vcruntime.lib:\u{240d}\n").unwrap();
        assert_eq!(
            searches["msvcrt"],
            BTreeSet::from(["C:\\VC\\msvcrt.lib".into()])
        );
        assert!(searched_paths("no native linker output").is_err());
        assert!(map_members("0001:00000200 symbol 0000000140001200 unknown-native.obj\n").is_err());
        let providers = BTreeMap::from([
            ("first/msvcrt.lib".into(), PathBuf::from("first")),
            ("second/msvcrt.lib".into(), PathBuf::from("second")),
        ]);
        assert!(unique_provider(providers, "msvcrt").is_err());
    }

    fn pe_fixture() -> Vec<u8> {
        let mut header = vec![0; 512];
        header[..2].copy_from_slice(b"MZ");
        header[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
        header[0x80..0x84].copy_from_slice(b"PE\0\0");
        header[0x84..0x86].copy_from_slice(&0x8664_u16.to_le_bytes());
        header[0x86..0x88].copy_from_slice(&1_u16.to_le_bytes());
        header[0x88..0x8c].copy_from_slice(&0x1234_5678_u32.to_le_bytes());
        header[0x94..0x96].copy_from_slice(&0xf0_u16.to_le_bytes());
        header[0x98..0x9a].copy_from_slice(&0x20b_u16.to_le_bytes());
        header[0xa8..0xac].copy_from_slice(&0x1234_u32.to_le_bytes());
        header[0xb0..0xb8].copy_from_slice(&0x1_4000_0000_u64.to_le_bytes());
        header[0x194..0x198].copy_from_slice(&0x1000_u32.to_le_bytes());
        header
    }

    #[test]
    fn stale_or_wrong_target_maps_do_not_bind_to_the_selected_pe_binary() {
        let map = "Timestamp is 12345678 (reproducible build file hash)\nPreferred load address is 0000000140000000\nentry point at 0001:00000234\n";
        let identity = map_binary_identity(&pe_fixture(), map, TARGET).unwrap();
        assert_eq!(
            identity,
            json!({"machine":0x8664,"timestamp":0x1234_5678,"image_base":0x1_4000_0000_u64,"entry_rva":0x1234})
        );
        for changed in [
            map.replace("12345678", "87654321"),
            map.replace("00000234", "00000235"),
            map.replace("0000000140000000", "0000000150000000"),
        ] {
            assert!(map_binary_identity(&pe_fixture(), &changed, TARGET).is_err());
        }
        assert!(map_binary_identity(&pe_fixture(), map, "aarch64-pc-windows-msvc").is_err());
        assert!(map_binary_identity(&pe_fixture()[..64], map, TARGET).is_err());
    }

    #[test]
    fn provider_drift_cannot_be_satisfied_by_an_installed_but_unselected_copy() {
        let root = "c:/program files/microsoft visual studio/18/enterprise";
        let relative = "vc/tools/msvc/14.51.36231/lib/x64/msvcrt.lib";
        assert_eq!(
            provider_relative_path(&format!("{root}/{relative}"), root).unwrap(),
            relative
        );
        assert!(provider_relative_path(&format!("d:/other/{relative}"), root).is_err());
        let expected = json!({"original_path":relative,"sha256":"a".repeat(64),"size":1234});
        validate_file_identity(&expected, relative, &"a".repeat(64), 1234).unwrap();
        assert!(validate_file_identity(&expected, relative, &"b".repeat(64), 1234).is_err());
        assert!(validate_file_identity(&expected, relative, &"a".repeat(64), 1235).is_err());
        assert!(
            validate_file_identity(
                &expected,
                &relative.replace("14.51.36231", "14.52.00000"),
                &"a".repeat(64),
                1234
            )
            .is_err()
        );
    }

    fn portable_fixture() -> (notices::Bundle, Value) {
        let linker = json!({"original_path":"VC/Tools/MSVC/14.51.36231/bin/HostX64/x64/link.exe","sha256":"a".repeat(64),"size":1234,"file_version":"14.51.36260.0"});
        let input = json!({"original_path":"VC/Tools/MSVC/14.51.36231/lib/x64/msvcrt.lib","sha256":"b".repeat(64),"size":4321,"role":"embedded-startup-support"});
        let bundle = notices::Bundle {
            index: json!({"components":[{"id":"runtime:synthetic-msvc","source":{"kind":KIND,"toolset_version":"14.51.36231","linker_file_version":"14.51.36260.0","target_linker_files":{(TARGET):linker},"target_input_files":{(TARGET):[input]}}}]}),
            files: BTreeMap::new(),
        };
        let mut observed = input;
        observed["members"] = json!(["exe_main.obj"]);
        let evidence = json!({"schema_version":1,"target":TARGET,"candidate":"c".repeat(40),"binary_sha256":"d".repeat(64),"component_id":"runtime:synthetic-msvc","selection":"configured-cli-action-and-native-map-search-trace","map_identity":{"machine":0x8664,"timestamp":0x1234_5678,"image_base":0x1_4000_0000_u64,"entry_rva":0x1234},"linker":linker,"inputs":[observed]});
        (bundle, evidence)
    }

    #[test]
    fn portable_evidence_rejects_changed_provider_pins_binary_and_scope() {
        let (bundle, evidence) = portable_fixture();
        validate(&bundle, &evidence, TARGET, &"c".repeat(40), &"d".repeat(64)).unwrap();
        for pointer in [
            "/candidate",
            "/binary_sha256",
            "/target",
            "/linker/sha256",
            "/linker/file_version",
            "/inputs/0/sha256",
            "/inputs/0/original_path",
        ] {
            let mut changed = evidence.clone();
            *changed.pointer_mut(pointer).unwrap() = json!("changed");
            assert!(
                validate(&bundle, &changed, TARGET, &"c".repeat(40), &"d".repeat(64)).is_err(),
                "accepted changed {pointer}"
            );
        }
        for members in [
            json!([]),
            json!(["../escape.obj"]),
            json!(["exe_main.obj", "exe_main.obj"]),
        ] {
            let mut changed = evidence.clone();
            changed["inputs"][0]["members"] = members;
            assert!(validate(&bundle, &changed, TARGET, &"c".repeat(40), &"d".repeat(64)).is_err());
        }
        let mut extra = evidence.clone();
        extra["inputs"]
            .as_array_mut()
            .unwrap()
            .push(evidence["inputs"][0].clone());
        assert!(validate(&bundle, &extra, TARGET, &"c".repeat(40), &"d".repeat(64)).is_err());
    }
}
