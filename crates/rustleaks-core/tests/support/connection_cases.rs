//! Authored positive cases for `rustleaks-connections-v1` password rules,
//! shared by `connection_rules.rs` and the all-rules precedence test.

pub const PREFIX: &str = "rustleaks.connection-string.password.";

/// (rule suffix, text before the secret, secret, text after it, match start)
/// for the input `p\nx={before}{secret}{after}`.
pub const FIVE_FORMS: [(&str, &str, &str, &str, usize); 5] = [
    ("unquoted", "Host=db.invalid;Pwd=", "R7!q", ";", 3),
    (
        "double-quoted",
        "Server=db.invalid;Password=\"",
        "R7;!q",
        "\";",
        3,
    ),
    (
        "single-quoted",
        "Data Source=db.invalid;Pwd='",
        "R7;!q",
        "';",
        3,
    ),
    ("odbc-braced", "DSN=synthetic;Pwd={", "R7}};!q", "};", 3),
    (
        "jdbc-query",
        "jdbc:postgresql://db.invalid/app?password=",
        "%52%37!q",
        "&",
        4,
    ),
];

pub const DATABASE_URI_SCHEMES: [&str; 5] =
    ["postgres", "postgresql", "mysql", "mariadb", "POSTGRESQL"];

pub const DATABASE_URI_SECRETS: [&str; 6] = [
    "7",
    "weak",
    "R7!q:more",
    "%52q7!",
    "%ZZq7!",
    "%24%7BPASSWORD%7D",
];

/// (rule suffix, text before the secret, text after it, secret offset) for
/// the input `{before}{secret}{after}dbname=application`.
pub const LIBPQ_FORMS: [(&str, &str, &str, usize); 2] = [
    ("quoted", "host=db.invalid user=bench password='", "' ", 37),
    ("unquoted", "host=db.invalid user=bench password=", " ", 36),
];

pub const LIBPQ_SECRETS: [&str; 5] = [
    "Q7v9R2m8K4p6T1w3Z5s0N2h4",
    "%517v9R2m8K4p6T1w3Z5s0N2h4",
    r"Q7\'v9R2",
    r"Q7\\v9R2",
    r"Q7\ v9R2",
];

/// One positive case: name, owning rule, input, file path, secret, and the
/// byte offset of the secret in the input.
pub type Positive = (String, String, String, &'static str, String, usize);

/// One positive per form, URI scheme and libpq form, using each table's
/// first secret where a table lists several.
pub fn positives() -> Vec<Positive> {
    let mut positives = Vec::new();
    for (suffix, before, secret, after, _) in FIVE_FORMS {
        positives.push((
            format!("{PREFIX}{suffix}/five-forms"),
            format!("{PREFIX}{suffix}"),
            format!("p\nx={before}{secret}{after}"),
            "",
            secret.to_owned(),
            4 + before.len(),
        ));
    }
    for scheme in DATABASE_URI_SCHEMES {
        let before = format!("{scheme}://app:");
        let secret = DATABASE_URI_SECRETS[2];
        positives.push((
            format!("{PREFIX}database-uri/{scheme}"),
            format!("{PREFIX}database-uri"),
            format!("p\nx={before}{secret}@db.invalid:5432/app?mode=rw"),
            "",
            secret.to_owned(),
            4 + before.len(),
        ));
    }
    for (suffix, before, after, offset) in LIBPQ_FORMS {
        let secret = LIBPQ_SECRETS[0];
        positives.push((
            format!("{PREFIX}libpq-{suffix}"),
            format!("{PREFIX}libpq-{suffix}"),
            format!("{before}{secret}{after}dbname=application"),
            "",
            secret.to_owned(),
            offset,
        ));
    }
    positives
}
