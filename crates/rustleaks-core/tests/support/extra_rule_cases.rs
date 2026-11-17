//! Authored positive cases for `rustleaks-extra-v1` rules, shared by
//! `native_rules.rs` and the all-rules precedence test.

pub const KEY: &str = "B7p4K9x2N6v1Q8s3T5w0Y4z7A2c6D9f1G8h3J5k0L4M=";

/// Each Azure rule with its three connection-string fields; the key field
/// holds [`KEY`].
pub fn azure_fields() -> [(&'static str, [String; 3]); 2] {
    [
        (
            "rustleaks.azure-servicebus-key",
            [
                "Endpoint=sb://synthetic.servicebus.windows.net/".to_owned(),
                "SharedAccessKeyName=synthetic".to_owned(),
                format!("SharedAccessKey={KEY}"),
            ],
        ),
        (
            "rustleaks.azure-app-configuration-key",
            [
                "Endpoint=https://synthetic.azconfig.io".to_owned(),
                "Id=synthetic-id".to_owned(),
                format!("Secret={KEY}"),
            ],
        ),
    ]
}

/// (URI, password) pairs for `rustleaks.mongodb-password`.
pub const MONGODB_URIS: [(&str, &str); 3] = [
    ("mongodb://synthetic:m7!@db.example.invalid/", "m7!"),
    (
        "mongodb+srv://synthetic:p8%40Q%3A9@cluster.example.invalid/",
        "p8%40Q%3A9",
    ),
    (
        "mongodb://synthetic:p8-Q9@one.example.invalid:27017,two.example.invalid:27018/",
        "p8-Q9",
    ),
];

/// One positive case: name, owning rule, input, file path, secret, and the
/// byte offset of the secret in the input.
pub type Positive = (String, String, String, &'static str, String, usize);

/// Each Azure rule with its fields in source order, and each `MongoDB` URI.
pub fn positives() -> Vec<Positive> {
    let mut positives = Vec::new();
    for (rule, fields) in azure_fields() {
        let input = fields.join(";");
        let start = input.len() - KEY.len();
        positives.push((
            format!("{rule}/fields"),
            rule.to_owned(),
            input,
            "",
            KEY.to_owned(),
            start,
        ));
    }
    for (index, (uri, password)) in MONGODB_URIS.into_iter().enumerate() {
        positives.push((
            format!("rustleaks.mongodb-password/{index}"),
            "rustleaks.mongodb-password".to_owned(),
            uri.to_owned(),
            "",
            password.to_owned(),
            uri.find(password).unwrap(),
        ));
    }
    positives
}
