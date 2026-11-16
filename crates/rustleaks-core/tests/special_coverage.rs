//! Independently specified optional connection, YAML and credential-context contracts.
#![forbid(unsafe_code)]
#![allow(missing_docs)]

use std::sync::OnceLock;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use rustleaks_core::config::{CompiledConfig, ConfigLoader, RawConfig};
use rustleaks_core::model::{ByteRange, Finding, FindingRange, Fragment, Location, ScanOptions};
use rustleaks_core::native::{
    CONNECTION_RULES_V1, EXTRA_RULES_V1, NativePolicy, PROVIDER_RULES_V1,
};
use rustleaks_core::{Engine, ScanBudget, ScanControl};
use serde::Deserialize;

#[derive(Deserialize)]
#[allow(clippy::struct_field_names)] // Field names mirror fixture JSON keys.
struct Cases {
    baseline_rule_ids: Vec<String>,
    selected_rule_ids: Vec<String>,
    primary: Vec<Case>,
    cases: Vec<Case>,
    tuples: Vec<TupleCase>,
    entropy: Vec<Entropy>,
}

#[derive(Deserialize)]
struct Entropy {
    rule: String,
    algorithm: String,
    reject: String,
    threshold: f64,
}

#[derive(Deserialize)]
struct Case {
    rule: String,
    name: String,
    input_base64: String,
    path: String,
    count: usize,
    expected: Vec<Record>,
    before_exact: Option<bool>,
    before_required: Option<Prior>,
    category: Option<String>,
}

#[derive(Deserialize)]
struct TupleCase {
    rule: String,
    helper: String,
    name: String,
    input_base64: String,
    path: String,
    max_decode_depth: usize,
    expected: Vec<Record>,
}

#[derive(Clone, Deserialize)]
struct Record {
    secret: String,
    #[serde(rename = "match")]
    matched: String,
    secret_range: Option<[usize; 2]>,
    match_range: Option<[usize; 2]>,
    location: Position,
    nested_secret: Option<String>,
    nested_match: Option<String>,
    #[serde(default)]
    nested_count: usize,
    nested_secret_range: Option<[usize; 2]>,
    nested_match_range: Option<[usize; 2]>,
    nested_location: Option<Position>,
}

#[derive(Deserialize)]
struct Prior {
    rule: String,
    secret: String,
    secret_range: [usize; 2],
}

#[derive(Clone, Deserialize)]
struct Position {
    start_line: usize,
    end_line: usize,
    start_column: usize,
    end_column: usize,
}

impl Position {
    fn coordinates(&self) -> [usize; 4] {
        [
            self.start_line,
            self.end_line,
            self.start_column,
            self.end_column,
        ]
    }
}

fn cases() -> &'static Cases {
    static CASES: OnceLock<Cases> = OnceLock::new();
    CASES.get_or_init(|| {
        serde_json::from_str(include_str!("support/special_coverage.json")).unwrap()
    })
}

const PRE_ASSOCIATION_IDS: [&str; 476] = [
    "1password-secret-key",
    "1password-service-account-token",
    "adafruit-api-key",
    "adobe-client-id",
    "adobe-client-secret",
    "age-secret-key",
    "airtable-api-key",
    "airtable-personnal-access-token",
    "algolia-api-key",
    "alibaba-access-key-id",
    "alibaba-secret-key",
    "anthropic-admin-api-key",
    "anthropic-api-key",
    "artifactory-api-key",
    "artifactory-reference-token",
    "asana-client-id",
    "asana-client-secret",
    "atlassian-api-token",
    "authress-service-client-access-key",
    "aws-access-token",
    "aws-amazon-bedrock-api-key-long-lived",
    "aws-amazon-bedrock-api-key-short-lived",
    "azure-ad-client-secret",
    "beamer-api-token",
    "bitbucket-client-id",
    "bitbucket-client-secret",
    "bittrex-access-key",
    "bittrex-secret-key",
    "cisco-meraki-api-key",
    "clickhouse-cloud-api-secret-key",
    "clojars-api-token",
    "cloudflare-api-key",
    "cloudflare-global-api-key",
    "cloudflare-origin-ca-key",
    "codecov-access-token",
    "cohere-api-token",
    "coinbase-access-token",
    "confluent-access-token",
    "confluent-secret-key",
    "contentful-delivery-api-token",
    "curl-auth-header",
    "curl-auth-user",
    "databricks-api-token",
    "datadog-access-token",
    "defined-networking-api-token",
    "digitalocean-access-token",
    "digitalocean-pat",
    "digitalocean-refresh-token",
    "discord-api-token",
    "discord-client-id",
    "discord-client-secret",
    "doppler-api-token",
    "droneci-access-token",
    "dropbox-api-token",
    "dropbox-long-lived-api-token",
    "dropbox-short-lived-api-token",
    "duffel-api-token",
    "dynatrace-api-token",
    "easypost-api-token",
    "easypost-test-api-token",
    "etsy-access-token",
    "facebook-access-token",
    "facebook-page-access-token",
    "facebook-secret",
    "fastly-api-token",
    "finicity-api-token",
    "finicity-client-secret",
    "finnhub-access-token",
    "flickr-access-token",
    "flutterwave-encryption-key",
    "flutterwave-public-key",
    "flutterwave-secret-key",
    "flyio-access-token",
    "frameio-api-token",
    "freemius-secret-key",
    "freshbooks-access-token",
    "gcp-api-key",
    "generic-api-key",
    "github-app-token",
    "github-fine-grained-pat",
    "github-oauth",
    "github-pat",
    "github-refresh-token",
    "gitlab-cicd-job-token",
    "gitlab-deploy-token",
    "gitlab-feature-flag-client-token",
    "gitlab-feed-token",
    "gitlab-incoming-mail-token",
    "gitlab-kubernetes-agent-token",
    "gitlab-oauth-app-secret",
    "gitlab-pat",
    "gitlab-pat-routable",
    "gitlab-ptt",
    "gitlab-rrt",
    "gitlab-runner-authentication-token",
    "gitlab-runner-authentication-token-routable",
    "gitlab-scim-token",
    "gitlab-session-cookie",
    "gitter-access-token",
    "gocardless-api-token",
    "grafana-api-key",
    "grafana-cloud-api-token",
    "grafana-service-account-token",
    "harness-api-key",
    "hashicorp-tf-api-token",
    "hashicorp-tf-password",
    "heroku-api-key",
    "heroku-api-key-v2",
    "hubspot-api-key",
    "huggingface-access-token",
    "huggingface-organization-api-token",
    "infracost-api-token",
    "intercom-api-key",
    "intra42-client-secret",
    "jfrog-api-key",
    "jfrog-identity-token",
    "jwt",
    "jwt-base64",
    "kraken-access-token",
    "kubernetes-secret-yaml",
    "kucoin-access-token",
    "kucoin-secret-key",
    "launchdarkly-access-token",
    "linear-api-key",
    "linear-client-secret",
    "linkedin-client-id",
    "linkedin-client-secret",
    "lob-api-key",
    "lob-pub-api-key",
    "looker-client-id",
    "looker-client-secret",
    "mailchimp-api-key",
    "mailgun-private-api-token",
    "mailgun-pub-key",
    "mailgun-signing-key",
    "mapbox-api-token",
    "mattermost-access-token",
    "maxmind-license-key",
    "messagebird-api-token",
    "messagebird-client-id",
    "microsoft-teams-webhook",
    "netlify-access-token",
    "new-relic-browser-api-token",
    "new-relic-insert-key",
    "new-relic-user-api-id",
    "new-relic-user-api-key",
    "notion-api-token",
    "npm-access-token",
    "nuget-config-password",
    "nytimes-access-token",
    "octopus-deploy-api-key",
    "okta-access-token",
    "openai-api-key",
    "openshift-user-token",
    "perplexity-api-key",
    "pkcs12-file",
    "plaid-api-token",
    "plaid-client-id",
    "plaid-secret-key",
    "planetscale-api-token",
    "planetscale-oauth-token",
    "planetscale-password",
    "postman-api-token",
    "prefect-api-token",
    "private-key",
    "privateai-api-token",
    "pulumi-api-token",
    "pypi-upload-token",
    "rapidapi-access-token",
    "readme-api-token",
    "rubygems-api-token",
    "scalingo-api-token",
    "sendbird-access-id",
    "sendbird-access-token",
    "sendgrid-api-token",
    "sendinblue-api-token",
    "sentry-access-token",
    "sentry-org-token",
    "sentry-user-token",
    "settlemint-application-access-token",
    "settlemint-personal-access-token",
    "settlemint-service-access-token",
    "shippo-api-token",
    "shopify-access-token",
    "shopify-custom-access-token",
    "shopify-private-app-access-token",
    "shopify-shared-secret",
    "sidekiq-secret",
    "sidekiq-sensitive-url",
    "slack-app-token",
    "slack-bot-token",
    "slack-config-access-token",
    "slack-config-refresh-token",
    "slack-legacy-bot-token",
    "slack-legacy-token",
    "slack-legacy-workspace-token",
    "slack-user-token",
    "slack-webhook-url",
    "snyk-api-token",
    "sonar-api-token",
    "sourcegraph-access-token",
    "square-access-token",
    "squarespace-access-token",
    "stripe-access-token",
    "sumologic-access-id",
    "sumologic-access-token",
    "telegram-bot-api-token",
    "travisci-access-token",
    "twilio-api-key",
    "twitch-api-token",
    "twitter-access-secret",
    "twitter-access-token",
    "twitter-api-key",
    "twitter-api-secret",
    "twitter-bearer-token",
    "typeform-api-token",
    "vault-batch-token",
    "vault-service-token",
    "yandex-access-token",
    "yandex-api-key",
    "yandex-aws-access-token",
    "zendesk-secret-key",
    "rustleaks.azure-servicebus-key",
    "rustleaks.azure-app-configuration-key",
    "rustleaks.mongodb-password",
    "rustleaks.groq-api-key",
    "rustleaks.cerebras-api-key",
    "rustleaks.replicate-api-token",
    "rustleaks.nvidia-api-key",
    "rustleaks.anthropic-api-key-escaped",
    "rustleaks.anthropic-admin-api-key-escaped",
    "rustleaks.digitalocean-refresh-token-escaped",
    "rustleaks.openai-api-key-20-segment",
    "rustleaks.flyio-flyv1",
    "rustleaks.cloudsmith-api-key",
    "rustleaks.minimax-api-key",
    "rustleaks.posthog-personal-api-key",
    "rustleaks.figma-personal-access-token",
    "rustleaks.togetherai-api-key",
    "rustleaks.gcp-gemini-api",
    "rustleaks.checkout-secret-key",
    "rustleaks.crates-io-api-key",
    "rustleaks.cursor-api-key",
    "rustleaks.databento-api-key",
    "rustleaks.elevenlabs-api-key",
    "rustleaks.figma-personal-access-header-token",
    "rustleaks.ollama-api-key",
    "rustleaks.polymarket-private-key",
    "rustleaks.slack-session-cookie",
    "rustleaks.slack-session-token",
    "rustleaks.stability-ai-api-key",
    "rustleaks.circleci-project-token",
    "rustleaks.deno-organization-token",
    "rustleaks.xai-api-key-80",
    "rustleaks.postman-collection-token",
    "rustleaks.dockerhub-personal-access-token",
    "rustleaks.dockerhub-organization-access-token",
    "rustleaks.neon-api-key",
    "rustleaks.render-api-key",
    "rustleaks.deno-account-token",
    "rustleaks.apify-api-token",
    "rustleaks.aws-amazon-bedrock-api-key-long-lived-delimiter",
    "rustleaks.digitalocean-access-token-delimiter",
    "rustleaks.gcp-api-key-delimiter",
    "rustleaks.huggingface-access-token-delimiter",
    "rustleaks.huggingface-organization-api-token-delimiter",
    "rustleaks.infracost-api-token-delimiter",
    "rustleaks.intra42-client-secret-delimiter",
    "rustleaks.maxmind-license-key-delimiter",
    "rustleaks.notion-api-token-delimiter",
    "rustleaks.octopus-deploy-api-key-delimiter",
    "rustleaks.planetscale-oauth-token-delimiter",
    "rustleaks.planetscale-password-delimiter",
    "rustleaks.prefect-api-token-delimiter",
    "rustleaks.pulumi-api-token-delimiter",
    "rustleaks.readme-api-token-delimiter",
    "rustleaks.rubygems-api-token-delimiter",
    "rustleaks.scalingo-api-token-delimiter",
    "rustleaks.settlemint-application-access-token-delimiter",
    "rustleaks.settlemint-personal-access-token-delimiter",
    "rustleaks.settlemint-service-access-token-delimiter",
    "rustleaks.shippo-api-token-delimiter",
    "rustleaks.square-access-token-delimiter",
    "rustleaks.vault-batch-token-delimiter",
    "rustleaks.vault-service-token-delimiter",
    "rustleaks.beamer-api-token-delimiter",
    "rustleaks.beamer-api-token-context-vt",
    "rustleaks.defined-networking-api-token-delimiter",
    "rustleaks.defined-networking-api-token-context-vt",
    "rustleaks.hashicorp-tf-password-delimiter",
    "rustleaks.hashicorp-tf-password-context-vt",
    "rustleaks.heroku-api-key-delimiter",
    "rustleaks.heroku-api-key-context-vt",
    "rustleaks.hubspot-api-key-delimiter",
    "rustleaks.hubspot-api-key-context-vt",
    "rustleaks.lob-api-key-delimiter",
    "rustleaks.lob-api-key-context-vt",
    "rustleaks.mailchimp-api-key-delimiter",
    "rustleaks.mailchimp-api-key-context-vt",
    "rustleaks.mailgun-private-api-token-delimiter",
    "rustleaks.mailgun-private-api-token-context-vt",
    "rustleaks.mailgun-signing-key-delimiter",
    "rustleaks.mailgun-signing-key-context-vt",
    "rustleaks.okta-access-token-delimiter",
    "rustleaks.okta-access-token-context-vt",
    "rustleaks.plaid-api-token-delimiter",
    "rustleaks.plaid-api-token-context-vt",
    "rustleaks.sidekiq-secret-delimiter",
    "rustleaks.sidekiq-secret-context-vt",
    "rustleaks.snyk-api-token-delimiter",
    "rustleaks.snyk-api-token-context-vt",
    "rustleaks.sonar-api-token-delimiter",
    "rustleaks.sonar-api-token-context-vt",
    "rustleaks.squarespace-access-token-delimiter",
    "rustleaks.squarespace-access-token-context-vt",
    "rustleaks.telegram-bot-api-token-delimiter",
    "rustleaks.telegram-bot-api-token-context-vt",
    "rustleaks.typeform-api-token-delimiter",
    "rustleaks.typeform-api-token-context-vt",
    "rustleaks.yandex-access-token-delimiter",
    "rustleaks.yandex-access-token-context-vt",
    "rustleaks.yandex-api-key-delimiter",
    "rustleaks.yandex-api-key-context-vt",
    "rustleaks.yandex-aws-access-token-delimiter",
    "rustleaks.yandex-aws-access-token-context-vt",
    "rustleaks.anthropic-api-key-vt",
    "rustleaks.anthropic-admin-api-key-vt",
    "rustleaks.digitalocean-refresh-token-vt",
    "rustleaks.openai-api-key-legacy-delimiter",
    "rustleaks.abuseipdb-api-key",
    "rustleaks.aikido-ci-token",
    "rustleaks.asaas-api-token",
    "rustleaks.brave-search-api-key",
    "rustleaks.buildkite-service-token",
    "rustleaks.buildkite-user-access-token",
    "rustleaks.canadian-digital-service-notify-api-key",
    "rustleaks.cartesia-api-key",
    "rustleaks.clerk-secret-key-delimiter",
    "rustleaks.clickup-personal-api-token",
    "rustleaks.cockroachlabs-cloud-api-key",
    "rustleaks.couchbase-capella-api-key",
    "rustleaks.datastax-astra-application-token",
    "rustleaks.devcycle-server-sdk-key",
    "rustleaks.devin-personal-api-key",
    "rustleaks.devin-service-api-key",
    "rustleaks.devin-service-user-token",
    "rustleaks.docker-swarm-join-token",
    "rustleaks.docker-swarm-unlock-key",
    "rustleaks.elastic-cloud-api-key",
    "rustleaks.endorlabs-api-key",
    "rustleaks.endorlabs-api-secret",
    "rustleaks.fal-api-key",
    "rustleaks.fullstory-api-key",
    "rustleaks.highnote-secret-live-key",
    "rustleaks.hunter-api-key",
    "rustleaks.ibm-cloud-user-api-key",
    "rustleaks.instantly-api-key",
    "rustleaks.ionic-personal-access-token",
    "rustleaks.kagi-api-key",
    "rustleaks.klaviyo-api-key",
    "rustleaks.labelbox-api-key",
    "rustleaks.labelbox-recursion-api-key",
    "rustleaks.langchain-langsmith-personal-access-token",
    "rustleaks.langchain-langsmith-service-key",
    "rustleaks.lichess-personal-access-token",
    "rustleaks.llama-cloud-api-key",
    "rustleaks.mailersend-api-token",
    "rustleaks.mem0-api-key",
    "rustleaks.mercury-production-api-token",
    "rustleaks.mergify-application-key",
    "rustleaks.midtrans-production-server-key",
    "rustleaks.miro-access-token",
    "rustleaks.ngrok-api-key",
    "rustleaks.nuget-api-key",
    "rustleaks.nylas-api-key",
    "rustleaks.onesignal-rich-authentication-token",
    "rustleaks.onfido-live-api-token-ca",
    "rustleaks.onfido-live-api-token-eu",
    "rustleaks.onfido-live-api-token-us",
    "rustleaks.opsgenie-api-key",
    "rustleaks.paddle-live-api-key",
    "rustleaks.pagerduty-authorization-token",
    "rustleaks.persona-production-api-key",
    "rustleaks.pinecone-api-key-uuid",
    "rustleaks.pinecone-api-key-pcsk",
    "rustleaks.pinterest-access-token",
    "rustleaks.polar-oauth-access-token",
    "rustleaks.polar-organization-access-token",
    "rustleaks.polar-personal-access-token",
    "rustleaks.postmark-api-token",
    "rustleaks.proof-full-access-api-key",
    "rustleaks.rainforest-pay-production-api-key",
    "rustleaks.redirect-pizza-api-token",
    "rustleaks.resend-api-key",
    "rustleaks.retell-api-key",
    "rustleaks.rootly-api-key",
    "rustleaks.runpod-api-key",
    "rustleaks.samsara-api-token",
    "rustleaks.scaleway-secret-key",
    "rustleaks.scalr-api-access-token-delimiter",
    "rustleaks.segment-public-api-token",
    "rustleaks.tailscale-api-key",
    "rustleaks.tailscale-auth-key",
    "rustleaks.tailscale-key",
    "rustleaks.tailscale-oauth-client-secret",
    "rustleaks.tailscale-scim-key",
    "rustleaks.tailscale-webhook-secret",
    "rustleaks.telnyx-api-v2-key",
    "rustleaks.upcloud-api-token",
    "rustleaks.virustotal-api-key",
    "rustleaks.voyageai-api-key",
    "rustleaks.vultr-api-key",
    "rustleaks.wakatime-api-key-uuid",
    "rustleaks.wakatime-api-key-prefixed",
    "rustleaks.woocommerce-consumer-secret",
    "rustleaks.workato-developer-api-token",
    "rustleaks.workos-production-api-key",
    "rustleaks.xendit-production-api-key",
    "rustleaks.zoho-oauth-token",
    "rustleaks.zoho-zapi-key",
    "rustleaks.zuplo-consumer-api-key",
    "rustleaks.supabase-management-token",
    "rustleaks.thunderstore-api-token",
    "rustleaks.unkey-root-key",
    "rustleaks.val-town-api-token",
    "rustleaks.temporal-cloud-api-key",
    "rustleaks.openrouter-api-key",
    "rustleaks.deepseek-api-key",
    "rustleaks.kimi-api-key",
    "rustleaks.zai-api-key",
    "rustleaks.gcp-adc-refresh-token",
    "rustleaks.adobe-client-secret-delimiter",
    "rustleaks.authress-service-client-access-key-boundary",
    "rustleaks.databricks-api-token-delimiter",
    "rustleaks.datadog-api-key",
    "rustleaks.datadog-application-key-delimiter",
    "rustleaks.etsy-open-api-key",
    "rustleaks.gitlab-incoming-mail-address-token",
    "rustleaks.gitlab-pat-routable-versioned",
    "rustleaks.gocardless-api-token-delimiter",
    "rustleaks.grafana-api-key-base64",
    "rustleaks.grafana-cloud-api-token-delimiter",
    "rustleaks.grafana-service-account-token-delimiter",
    "rustleaks.heroku-api-key-v2-trailing-hyphen-delimiter",
    "rustleaks.monday-api-token",
    "rustleaks.sendinblue-api-token-boundary",
    "rustleaks.sourcegraph-access-token-delimiter",
    "rustleaks.stripe-access-token-delimiter",
    "rustleaks.digitalocean-pat-boundary",
    "rustleaks.hcp-client-secret",
    "rustleaks.heroku-platform-key-boundary",
    "rustleaks.npm-access-token-boundary",
    "rustleaks.openrouter-api-key-boundary",
    "rustleaks.packagist-organization-read-token",
    "rustleaks.packagist-organization-update-token",
    "rustleaks.postman-api-token-boundary",
    "rustleaks.sendgrid-api-token-boundary",
    "rustleaks.slack-config-refresh-token-147",
    "rustleaks.azure-app-configuration-key-comma",
    "rustleaks.azure-servicebus-key-comma",
    "rustleaks.azure-servicebus-key-comma-tuple",
    "rustleaks.jwt-unsigned-bearer-escaped",
    "rustleaks.kubernetes-secret-yaml-long-context",
    "rustleaks.cloudflare-api-token-context",
    "rustleaks.connection-string.password.double-quoted",
    "rustleaks.connection-string.password.single-quoted",
    "rustleaks.connection-string.password.odbc-braced",
    "rustleaks.connection-string.password.unquoted",
    "rustleaks.connection-string.password.jdbc-query",
    "rustleaks.connection-string.password.database-uri",
    "rustleaks.bitbucket-git-credentials",
    "rustleaks.codecatalyst-git-credentials",
    "rustleaks.codecommit-git-credentials",
    "rustleaks.mongodb-password-comma",
    "rustleaks.mongodb-password-comma-tuple",
    "rustleaks.service-uri-password",
];

fn config() -> &'static CompiledConfig {
    static CONFIG: OnceLock<CompiledConfig> = OnceLock::new();
    CONFIG.get_or_init(|| {
        NativePolicy::builder()
            .with_pack("rustleaks-providers-v1", PROVIDER_RULES_V1)
            .unwrap()
            .with_pack("rustleaks-connections-v1", CONNECTION_RULES_V1)
            .unwrap()
            .with_pack("rustleaks-extra-v1", EXTRA_RULES_V1)
            .unwrap()
            .compile()
            .unwrap()
            .0
            .select_rules(PRE_ASSOCIATION_IDS)
            .unwrap()
    })
}

fn selected() -> &'static Engine {
    static ENGINE: OnceLock<Engine> = OnceLock::new();
    ENGINE.get_or_init(|| {
        Engine::builder(
            config()
                .select_rules(cases().selected_rule_ids.iter().map(String::as_str))
                .unwrap(),
        )
        .build()
        .unwrap()
    })
}

fn composed() -> &'static Engine {
    static ENGINE: OnceLock<Engine> = OnceLock::new();
    ENGINE.get_or_init(|| Engine::builder(config().clone()).build().unwrap())
}

fn previous() -> &'static Engine {
    static ENGINE: OnceLock<Engine> = OnceLock::new();
    ENGINE.get_or_init(|| {
        let config = config()
            .select_rules(cases().baseline_rule_ids.iter().map(String::as_str))
            .unwrap();
        assert_eq!(config.rules().len(), 467);
        Engine::builder(config).build().unwrap()
    })
}

fn range(value: Option<[usize; 2]>) -> FindingRange {
    value.map_or(FindingRange::Unavailable, |[start, end]| {
        FindingRange::Exact(ByteRange::new(start, end).unwrap())
    })
}

fn scan(engine: &Engine, input: &[u8], path: &str) -> Vec<Finding> {
    let fragment = Fragment::builder(input).file_path(path).build();
    let result = engine.scan_fragment(&fragment, &ScanOptions::default());
    assert!(result.is_complete());
    result.findings().to_vec()
}

fn for_rule<'a>(findings: &'a [Finding], rule: &str) -> Vec<&'a Finding> {
    findings
        .iter()
        .filter(|finding| finding.rule_id().as_bytes() == rule.as_bytes())
        .collect()
}

fn coordinates(value: Location) -> [usize; 4] {
    [
        value.start_line(),
        value.end_line(),
        value.start_column(),
        value.end_column(),
    ]
}

fn assert_record(rule: &str, expected: &Record, finding: &Finding, name: &str) {
    assert_eq!(
        finding.secret().as_bytes(),
        expected.secret.as_bytes(),
        "{name}"
    );
    assert_eq!(
        finding.match_text().as_bytes(),
        expected.matched.as_bytes(),
        "{name}"
    );
    assert_eq!(
        finding.secret_range(),
        range(expected.secret_range),
        "{name}"
    );
    assert_eq!(finding.match_range(), range(expected.match_range), "{name}");
    assert_eq!(
        coordinates(finding.location()),
        expected.location.coordinates(),
        "{name}"
    );
    assert_eq!(
        finding.required_findings().len(),
        expected.nested_count,
        "{name}"
    );
    if expected.nested_count == 1 {
        let nested = &finding.required_findings()[0];
        assert_eq!(
            nested.rule_id().as_bytes(),
            format!("{rule}-tuple").as_bytes(),
            "{name}"
        );
        assert_eq!(
            nested.secret().as_bytes(),
            expected.nested_secret.as_ref().unwrap().as_bytes(),
            "{name}"
        );
        assert_eq!(
            nested.match_text().as_bytes(),
            expected.nested_match.as_ref().unwrap().as_bytes(),
            "{name}"
        );
        assert_eq!(
            nested.secret_range(),
            range(expected.nested_secret_range),
            "{name}"
        );
        assert_eq!(
            nested.match_range(),
            range(expected.nested_match_range),
            "{name}"
        );
        assert_eq!(
            coordinates(nested.location()),
            expected.nested_location.as_ref().unwrap().coordinates(),
            "{name}"
        );
    }
}

fn assert_records(rule: &str, expected: &[Record], findings: &[Finding], name: &str) {
    let mut actual = for_rule(findings, rule);
    assert_eq!(actual.len(), expected.len(), "{name}");
    for record in expected {
        let index = actual
            .iter()
            .position(|finding| {
                finding.secret().as_bytes() == record.secret.as_bytes()
                    && finding.match_text().as_bytes() == record.matched.as_bytes()
                    && finding.secret_range() == range(record.secret_range)
                    && coordinates(finding.location()) == record.location.coordinates()
            })
            .unwrap_or_else(|| panic!("missing exact finding: {name}"));
        assert_record(rule, record, actual.remove(index), name);
    }
}

#[test]
fn every_concrete_family_case_and_endpoint_has_exact_independent_expectations() {
    assert_eq!(config().rules().len(), 476);
    assert_eq!(selected().config().rules().len(), 9);
    assert_eq!(cases().primary.len(), 18);
    assert_eq!(cases().cases.len(), 217);
    assert_eq!(
        cases()
            .cases
            .iter()
            .filter(|case| case.category.as_deref() == Some("document_boundary"))
            .count(),
        48
    );
    assert_eq!(
        cases()
            .cases
            .iter()
            .filter(|case| case.category.as_deref() == Some("non_marker_boundary_controls"))
            .count(),
        12
    );
    for case in cases().primary.iter().chain(&cases().cases) {
        assert_eq!(case.count, case.expected.len(), "{}", case.name);
        let findings = scan(
            selected(),
            &STANDARD.decode(&case.input_base64).unwrap(),
            &case.path,
        );
        assert_records(&case.rule, &case.expected, &findings, &case.name);
        assert!(
            findings
                .iter()
                .all(|finding| !finding.rule_id().as_bytes().ends_with(b"-tuple"))
        );
    }
}

#[test]
fn native_tuple_identity_retains_each_parent_and_only_its_own_helper() {
    assert_eq!(cases().tuples.len(), 22);
    for case in &cases().tuples {
        let input = STANDARD.decode(&case.input_base64).unwrap();
        let fragment = Fragment::builder(input.as_slice())
            .file_path(case.path.as_str())
            .build();
        let options = ScanOptions::builder()
            .max_decode_depth(case.max_decode_depth)
            .build();
        for engine in [selected(), composed()] {
            let result = engine.scan_fragment(&fragment, &options);
            assert!(result.is_complete(), "{}", case.name);
            assert_records(&case.rule, &case.expected, result.findings(), &case.name);
            assert!(for_rule(result.findings(), &case.helper).is_empty());
        }
    }
}

#[test]
fn helper_selection_and_native_entropy_cannot_be_bypassed() {
    assert_eq!(cases().entropy.len(), 5);
    for expected in &cases().entropy {
        assert_eq!(
            config().rule(&expected.rule).unwrap().native_entropy(),
            Some((
                expected.algorithm.as_str(),
                expected.reject.as_str(),
                expected.threshold
            ))
        );
    }
    for rule in [
        "rustleaks.azure-servicebus-key-comma",
        "rustleaks.mongodb-password-comma",
    ] {
        let helper = format!("{rule}-tuple");
        let case = cases()
            .primary
            .iter()
            .find(|case| case.rule == rule)
            .unwrap();
        let input = STANDARD.decode(&case.input_base64).unwrap();
        let parent_only = Engine::builder(config().select_rules([rule]).unwrap())
            .build()
            .unwrap();
        assert!(scan(&parent_only, &input, &case.path).is_empty());
        let helper_only = Engine::builder(config().select_rules([helper.as_str()]).unwrap())
            .build()
            .unwrap();
        assert!(scan(&helper_only, &input, &case.path).is_empty());
        let pair = Engine::builder(config().select_rules([rule, helper.as_str()]).unwrap())
            .build()
            .unwrap();
        assert_records(
            rule,
            &case.expected,
            &scan(&pair, &input, &case.path),
            &case.name,
        );
    }
    assert!(ConfigLoader::new().load_toml(PROVIDER_RULES_V1).is_err());
    assert!(ConfigLoader::new().load_toml(CONNECTION_RULES_V1).is_err());
}

#[test]
fn complete_composition_preserves_prior_occurrences_and_accounts_for_new_secrets() {
    for case in cases().primary.iter().chain(
        cases()
            .cases
            .iter()
            .filter(|case| case.before_required.is_some()),
    ) {
        let input = STANDARD.decode(&case.input_base64).unwrap();
        let prior = scan(previous(), &input, &case.path);
        let after = scan(composed(), &input, &case.path);
        assert_records(&case.rule, &case.expected, &after, &case.name);
        if let Some(exact_before) = case.before_exact {
            let expected = &case.expected[0];
            let exact = |finding: &&Finding| {
                finding.secret().as_bytes() == expected.secret.as_bytes()
                    && finding.secret_range() == range(expected.secret_range)
            };
            assert_eq!(
                prior.iter().filter(exact).count() > 0,
                exact_before,
                "{}",
                case.name
            );
            assert_eq!(after.iter().filter(exact).count(), 1, "{}", case.name);
        }
        if let Some(required) = &case.before_required {
            for findings in [&prior, &after] {
                assert!(
                    findings.iter().any(|finding| finding.rule_id().as_bytes()
                        == required.rule.as_bytes()
                        && finding.secret().as_bytes() == required.secret.as_bytes()
                        && finding.secret_range() == range(Some(required.secret_range))),
                    "{}",
                    case.name
                );
            }
        }
        for finding in &prior {
            if finding.rule_id().as_bytes() == b"generic-api-key" {
                continue;
            }
            assert!(
                after.iter().any(|next| next.rule_id() == finding.rule_id()
                    && next.secret() == finding.secret()
                    && next.secret_range() == finding.secret_range()
                    && next.match_range() == finding.match_range()),
                "{}",
                case.name
            );
        }
    }
}

fn added_rules() -> Vec<toml::Value> {
    [PROVIDER_RULES_V1, CONNECTION_RULES_V1]
        .into_iter()
        .flat_map(|source| {
            let source: toml::Value = toml::from_str(source).unwrap();
            source["rules"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|rule| {
                    cases()
                        .selected_rule_ids
                        .iter()
                        .any(|id| Some(id.as_str()) == rule["id"].as_str())
                })
                .cloned()
                .collect::<Vec<_>>()
        })
        .collect()
}

fn local_allowlist(predicate: &toml::Value) -> Engine {
    let mut rules = added_rules();
    for rule in &mut rules {
        rule.as_table_mut()
            .unwrap()
            .entry("allowlists")
            .or_insert_with(|| toml::Value::Array(Vec::new()))
            .as_array_mut()
            .unwrap()
            .push(predicate.clone());
    }
    let mut source = toml::Table::new();
    source.insert("rules".into(), toml::Value::Array(rules));
    let (config, _) = NativePolicy::builder()
        .with_pack(
            "special-allowlist-controls",
            &toml::to_string(&source).unwrap(),
        )
        .unwrap()
        .compile()
        .unwrap();
    Engine::builder(
        config
            .select_rules(cases().selected_rule_ids.iter().map(String::as_str))
            .unwrap(),
    )
    .build()
    .unwrap()
}

fn exact_pattern(value: &str) -> String {
    use std::fmt::Write as _;
    let mut pattern = String::from("^");
    for byte in value.bytes() {
        write!(pattern, "\\x{byte:02x}").unwrap();
    }
    pattern.push('$');
    pattern
}

#[test]
fn local_allowlists_preserve_targets_stopwords_commit_neighbors_and_markers() {
    for target in ["secret", "match", "line"] {
        let engine = local_allowlist(
            &toml::from_str(&format!("regexTarget='{target}'\nregexes=['.']")).unwrap(),
        );
        for case in &cases().primary {
            assert!(
                scan(
                    &engine,
                    &STANDARD.decode(&case.input_base64).unwrap(),
                    &case.path
                )
                .is_empty()
            );
        }
    }
    for case in &cases().primary {
        let expected = &case.expected[0];
        let middle = expected.secret.len() / 2;
        let mut predicate = toml::Table::new();
        predicate.insert(
            "stopwords".into(),
            toml::Value::Array(vec![toml::Value::String(
                expected.secret[middle..middle + 4].to_ascii_uppercase(),
            )]),
        );
        let engine = local_allowlist(&toml::Value::Table(predicate));
        let input = STANDARD.decode(&case.input_base64).unwrap();
        assert!(for_rule(&scan(&engine, &input, &case.path), &case.rule).is_empty());
        let engine =
            local_allowlist(&toml::from_str("commits=['synthetic-special-commit']").unwrap());
        for (commit, count) in [
            ("synthetic-special-commit", 0),
            ("synthetic-special-neighbor", 1),
        ] {
            let fragment = Fragment::builder(input.as_slice())
                .file_path(case.path.as_str())
                .commit(commit)
                .build();
            let result = engine.scan_fragment(&fragment, &ScanOptions::default());
            assert!(result.is_complete());
            assert_eq!(
                for_rule(result.findings(), &case.rule).len(),
                count,
                "{}",
                case.name
            );
        }
        // Markers are line-scoped; YAML's multi-line match is exercised by
        // explicit local predicates above rather than a trailing-line marker.
        if !input.contains(&b'\n') {
            let mut marked = input.clone();
            marked.extend_from_slice(b" # rustleaks:allow");
            let mut marker_expected = case.expected.clone();
            if case.rule == "rustleaks.service-uri-password" {
                // The source URI path greedily includes the final semicolon.
                // Appending the marker replaces the EOF terminal with one
                // consumed space; the password capture remains unchanged.
                for expected in &mut marker_expected {
                    let [start, end] = expected.match_range.unwrap();
                    assert_eq!(end, input.len());
                    assert!(expected.matched.ends_with(';'));
                    expected.matched.push(' ');
                    expected.match_range = Some([start, end + 1]);
                    expected.location.end_column += 1;
                }
            }
            assert!(for_rule(&scan(selected(), &marked, &case.path), &case.rule).is_empty());
            let fragment = Fragment::builder(marked.as_slice())
                .file_path(case.path.as_str())
                .build();
            let result = selected().scan_fragment(
                &fragment,
                &ScanOptions::builder().honor_allow_markers(false).build(),
            );
            assert!(result.is_complete());
            assert_records(&case.rule, &marker_expected, result.findings(), &case.name);
        }
    }
}

#[test]
fn global_target_and_commit_controls_keep_their_unrelated_positive_cases() {
    // Native packs cannot add global predicates. This ordinary-config control
    // retains each reporting expression and local filters while removing
    // native entropy/association metadata. It isolates global semantics; the
    // native tuple and entropy contracts are checked separately above.
    for case in &cases().primary {
        let mut rule = added_rules()
            .into_iter()
            .find(|rule| rule["id"].as_str() == Some(case.rule.as_str()))
            .unwrap();
        rule.as_table_mut().unwrap().remove("entropy");
        rule.as_table_mut().unwrap().remove("required");
        for (target, count) in [(case.rule.as_str(), 0), ("unrelated-special-control", 1)] {
            let mut source = toml::Table::new();
            let neighbor: toml::Value = toml::from_str(
                "id='unrelated-special-control'\nregex='NEVER_A_SPECIAL_CREDENTIAL'",
            )
            .unwrap();
            source.insert(
                "rules".into(),
                toml::Value::Array(vec![rule.clone(), neighbor]),
            );
            let mut predicate = toml::Table::new();
            predicate.insert(
                "targetRules".into(),
                toml::Value::Array(vec![toml::Value::String(target.into())]),
            );
            predicate.insert("regexTarget".into(), toml::Value::String("secret".into()));
            predicate.insert(
                "regexes".into(),
                toml::Value::Array(vec![toml::Value::String(exact_pattern(
                    &case.expected[0].secret,
                ))]),
            );
            source.insert(
                "allowlists".into(),
                toml::Value::Array(vec![toml::Value::Table(predicate)]),
            );
            let raw: RawConfig = toml::from_str(&toml::to_string(&source).unwrap()).unwrap();
            let engine = Engine::builder(ConfigLoader::new().compile(raw).unwrap())
                .build()
                .unwrap();
            assert_eq!(
                scan(
                    &engine,
                    &STANDARD.decode(&case.input_base64).unwrap(),
                    &case.path
                )
                .len(),
                count,
                "{}",
                case.name
            );
        }
        let mut source = toml::Table::new();
        source.insert("rules".into(), toml::Value::Array(vec![rule]));
        source.insert(
            "allowlists".into(),
            toml::Value::Array(vec![
                toml::from_str("commits=['synthetic-special-commit']").unwrap(),
            ]),
        );
        let raw: RawConfig = toml::from_str(&toml::to_string(&source).unwrap()).unwrap();
        let engine = Engine::builder(ConfigLoader::new().compile(raw).unwrap())
            .build()
            .unwrap();
        let input = STANDARD.decode(&case.input_base64).unwrap();
        for (commit, count) in [
            ("synthetic-special-commit", 0),
            ("synthetic-special-neighbor", 1),
        ] {
            let fragment = Fragment::builder(input.as_slice())
                .file_path(case.path.as_str())
                .commit(commit)
                .build();
            let result = engine.scan_fragment(&fragment, &ScanOptions::default());
            assert!(result.is_complete());
            assert_eq!(result.findings().len(), count);
        }
    }
}

#[test]
fn every_special_family_obeys_work_record_payload_and_target_limits() {
    for case in &cases().primary {
        let input = STANDARD.decode(&case.input_base64).unwrap();
        let fragment = Fragment::builder(input.as_slice())
            .file_path(case.path.as_str())
            .build();
        for budget in [
            ScanBudget::unlimited().max_finding_payload_bytes(1),
            ScanBudget::unlimited().max_finding_records(0),
            ScanBudget::unlimited().max_work_units(0),
        ] {
            let result = selected().scan_fragment_controlled(
                &fragment,
                &ScanOptions::default(),
                &ScanControl::unlimited().with_budget(budget),
            );
            assert!(!result.is_complete(), "{}", case.name);
            assert!(result.findings().is_empty());
        }
        for (size, count) in [(input.len() - 1, 0), (input.len(), 1)] {
            let result = selected().scan_fragment(
                &fragment,
                &ScanOptions::builder().max_target_bytes(Some(size)).build(),
            );
            assert!(result.is_complete());
            assert_eq!(
                for_rule(result.findings(), &case.rule).len(),
                count,
                "{}",
                case.name
            );
        }
        for repetitions in [100, 10_000] {
            let mut repeated = Vec::new();
            for _ in 0..repetitions {
                repeated.extend_from_slice(&input);
                repeated.push(b'\n');
            }
            let fragment = Fragment::builder(repeated.as_slice())
                .file_path(case.path.as_str())
                .build();
            let result = selected().scan_fragment_controlled(
                &fragment,
                &ScanOptions::default(),
                &ScanControl::unlimited().with_budget(ScanBudget::unlimited().max_work_units(1)),
            );
            assert!(!result.is_complete(), "{}", case.name);
            if repetitions == 100 {
                let result = selected().scan_fragment(&fragment, &ScanOptions::default());
                assert!(result.is_complete());
                let findings = for_rule(result.findings(), &case.rule);
                assert_eq!(findings.len(), repetitions, "{}", case.name);
                let [start, end] = case.expected[0].secret_range.unwrap();
                for index in 0..repetitions {
                    let offset = index * (input.len() + 1);
                    assert!(
                        findings.iter().any(|finding| finding.secret().as_bytes()
                            == case.expected[0].secret.as_bytes()
                            && finding.secret_range()
                                == range(Some([offset + start, offset + end]))),
                        "{}",
                        case.name
                    );
                }
            }
        }
    }
}

#[test]
fn long_valid_json_payloads_and_uri_tails_keep_exact_secrets_and_budget_failures() {
    for length in [8_192, 262_144] {
        let token = ["9Z7q2M8v4R1x6B5", "n3T0DkWcYpSgJfUa"]
            .concat()
            .chars()
            .cycle()
            .take(length)
            .collect::<String>();
        let payload = serde_json::json!({"iss":"https://identity.internal","sub":"service-27","aud":"deployment-api","jti":token});
        let secret = format!(
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.{}.",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap())
        );
        let jwt = format!("Authorization: Bearer {secret}\\\"");
        let uri_secret = ["A7q2M9z4", "B6w8C3v5"].concat();
        let uri = format!(
            "redis://alice:{uri_secret}@cache.internal/{};",
            "path7".repeat(length / 5)
        );
        for (rule, input, expected_secret, start) in [
            (
                "rustleaks.jwt-unsigned-bearer-escaped",
                jwt.as_str(),
                secret.as_str(),
                22,
            ),
            (
                "rustleaks.service-uri-password",
                uri.as_str(),
                uri_secret.as_str(),
                14,
            ),
        ] {
            let findings = scan(selected(), input.as_bytes(), "runtime/service.conf");
            let findings = for_rule(&findings, rule);
            assert_eq!(findings.len(), 1, "{rule} {length}");
            assert_eq!(findings[0].secret().as_bytes(), expected_secret.as_bytes());
            assert_eq!(
                findings[0].secret_range(),
                range(Some([start, start + expected_secret.len()]))
            );
            assert_eq!(findings[0].match_range(), range(Some([0, input.len()])));
            let fragment = Fragment::new(input.as_bytes());
            for budget in [
                ScanBudget::unlimited().max_finding_payload_bytes(1_024),
                ScanBudget::unlimited().max_work_units(0),
            ] {
                let result = selected().scan_fragment_controlled(
                    &fragment,
                    &ScanOptions::default(),
                    &ScanControl::unlimited().with_budget(budget),
                );
                assert!(!result.is_complete(), "{rule} {length}");
                assert!(result.findings().is_empty());
            }
        }
    }
}

#[test]
fn mongodb_whole_tuple_entropy_rejection_is_not_masked_by_source_filters() {
    let rule = "rustleaks.mongodb-password-comma";
    let helper = "rustleaks.mongodb-password-comma-tuple";
    let negative = cases()
        .cases
        .iter()
        .find(|case| case.rule == rule && case.name.contains("entropy_reject"))
        .unwrap();
    let positive = cases()
        .cases
        .iter()
        .find(|case| case.name == "mongodb-tuple-entropy-positive-neighbor")
        .unwrap();
    let input = STANDARD.decode(&negative.input_base64).unwrap();
    assert!(for_rule(&scan(selected(), &input, &negative.path), rule).is_empty());
    assert_records(
        rule,
        &positive.expected,
        &scan(
            selected(),
            &STANDARD.decode(&positive.input_base64).unwrap(),
            &positive.path,
        ),
        &positive.name,
    );

    // Remove exactly the helper entropy predicate. All parent/helper regexes,
    // source filters, association and inherited policy remain active.
    let mut rules = added_rules();
    let tuple = rules
        .iter_mut()
        .find(|value| value["id"].as_str() == Some(helper))
        .unwrap();
    assert!(tuple.as_table_mut().unwrap().remove("entropy").is_some());
    let mut source = toml::Table::new();
    source.insert("rules".into(), toml::Value::Array(rules));
    let (config, _) = NativePolicy::builder()
        .with_pack(
            "special-entropy-control",
            &toml::to_string(&source).unwrap(),
        )
        .unwrap()
        .compile()
        .unwrap();
    assert_eq!(config.rule(helper).unwrap().native_entropy(), None);
    let engine = Engine::builder(config.select_rules([rule, helper]).unwrap())
        .build()
        .unwrap();
    let findings = scan(&engine, &input, &negative.path);
    assert_eq!(findings.len(), 1);
    let finding = &findings[0];
    assert_eq!(finding.rule_id().as_bytes(), rule.as_bytes());
    assert_eq!(finding.secret().as_bytes(), b"A7q2M9z4B6w8C3v5");
    assert_eq!(finding.secret_range(), range(Some([16, 32])));
    assert_eq!(finding.match_text().as_bytes(), input.as_slice());
    assert_eq!(finding.match_range(), range(Some([0, input.len()])));
    assert_eq!(coordinates(finding.location()), [0, 0, 1, input.len()]);
    assert_eq!(finding.required_findings().len(), 1);
    let nested = &finding.required_findings()[0];
    assert_eq!(nested.rule_id().as_bytes(), helper.as_bytes());
    assert_eq!(nested.secret().as_bytes(), &input[..input.len() - 2]);
    assert_eq!(nested.secret_range(), range(Some([0, input.len() - 2])));
    assert_eq!(nested.match_text().as_bytes(), input.as_slice());
    assert_eq!(nested.match_range(), range(Some([0, input.len()])));
    assert_eq!(coordinates(nested.location()), [0, 0, 1, input.len()]);
}

fn ordinary_single_rule(rule: toml::Value) -> Engine {
    let mut source = toml::Table::new();
    source.insert("rules".into(), toml::Value::Array(vec![rule]));
    let raw: RawConfig = toml::from_str(&toml::to_string(&source).unwrap()).unwrap();
    Engine::builder(ConfigLoader::new().compile(raw).unwrap())
        .build()
        .unwrap()
}

#[test]
fn yaml_source_and_inherited_paths_are_independent_of_its_required_suffix() {
    let id = "rustleaks.kubernetes-secret-yaml-long-context";
    let original = added_rules()
        .into_iter()
        .find(|rule| rule["id"].as_str() == Some(id))
        .unwrap();
    let local = ordinary_single_rule(original.clone());
    let mut without_local_paths = original;
    let predicates = without_local_paths["allowlists"].as_array_mut().unwrap();
    let before = predicates.len();
    predicates.retain(|predicate| !predicate.as_table().unwrap().contains_key("paths"));
    assert_eq!(predicates.len() + 1, before);
    // Preserve the positive .yaml/.yml requirement and every non-path filter.
    assert_eq!(without_local_paths["path"].as_str(), Some(r"(?i)\.ya?ml$"));
    let lexical = ordinary_single_rule(without_local_paths.clone());
    let mut source = toml::Table::new();
    source.insert(
        "rules".into(),
        toml::Value::Array(vec![without_local_paths]),
    );
    let (config, _) = NativePolicy::builder()
        .with_pack(
            "special-yaml-path-control",
            &toml::to_string(&source).unwrap(),
        )
        .unwrap()
        .compile()
        .unwrap();
    let inherited = Engine::builder(config.select_rules([id]).unwrap())
        .build()
        .unwrap();
    let case = cases()
        .cases
        .iter()
        .find(|case| case.name == "kubernetes-path-positive-neighbor")
        .unwrap();
    let input = STANDARD.decode(&case.input_base64).unwrap();
    for path in [
        "vendor/github.com/fixture/secret.yaml",
        "node_modules/runtime/service.yaml",
    ] {
        assert!(
            scan(&local, &input, path).is_empty(),
            "local source filter: {path}"
        );
        assert_records(id, &case.expected, &scan(&lexical, &input, path), path);
        assert!(
            scan(&inherited, &input, path).is_empty(),
            "inherited global filter: {path}"
        );
    }
    for engine in [&local, &lexical, &inherited] {
        assert_records(
            id,
            &case.expected,
            &scan(engine, &input, "runtime/service.yaml"),
            "path neighbor",
        );
    }
}
