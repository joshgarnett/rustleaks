//! Independent synthetic contracts for optional credential format supplements.
#![forbid(unsafe_code)]
#![allow(missing_docs)]

use std::sync::OnceLock;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
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
    primary: Vec<Case>,
    cases: Vec<Case>,
    entropy: Vec<Entropy>,
    contracts: Vec<RuleContract>,
}

#[derive(Deserialize)]
struct RuleContract {
    rule: String,
    keywords: Vec<String>,
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
    secret: Option<String>,
    #[serde(rename = "match")]
    matched: Option<String>,
    secret_range: Option<[usize; 2]>,
    match_range: Option<[usize; 2]>,
    secret_ranges: Option<Vec<[usize; 2]>>,
    location: Option<Position>,
    before_occurrence: Option<bool>,
    before_exact: Option<bool>,
    before_required: Option<Required>,
}

#[derive(Deserialize)]
struct Required {
    rule: String,
    secret: String,
    secret_range: [usize; 2],
    #[serde(rename = "match")]
    matched: Option<String>,
    match_range: Option<[usize; 2]>,
    location: Option<Position>,
}

#[derive(Deserialize)]
struct Position {
    start_line: usize,
    end_line: usize,
    start_column: usize,
    end_column: usize,
}

impl Position {
    fn location(&self) -> Location {
        Location::new(
            self.start_line,
            self.end_line,
            self.start_column,
            self.end_column,
        )
        .unwrap()
    }
}

fn cases() -> &'static Cases {
    static CASES: OnceLock<Cases> = OnceLock::new();
    CASES
        .get_or_init(|| serde_json::from_str(include_str!("support/format_coverage.json")).unwrap())
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
                .select_rules(cases().primary.iter().map(|case| case.rule.as_str()))
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
        assert_eq!(config.rules().len(), 440);
        Engine::builder(config).build().unwrap()
    })
}

fn range([start, end]: [usize; 2]) -> FindingRange {
    FindingRange::Exact(ByteRange::new(start, end).unwrap())
}

fn scan(engine: &Engine, bytes: &[u8], path: &str) -> Vec<Finding> {
    let fragment = Fragment::builder(bytes).file_path(path).build();
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

fn assert_case(case: &Case, findings: &[Finding]) {
    let findings = for_rule(findings, &case.rule);
    assert_eq!(findings.len(), case.count, "{}", case.name);
    if let Some(ranges) = &case.secret_ranges {
        assert_eq!(findings.len(), ranges.len(), "{}", case.name);
        for expected in ranges {
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.secret_range() == range(*expected)),
                "{}",
                case.name
            );
        }
    }
    if findings.len() != 1 {
        return;
    }
    let finding = findings[0];
    if let Some(secret) = &case.secret {
        assert_eq!(
            finding.secret().as_bytes(),
            secret.as_bytes(),
            "{}",
            case.name
        );
    }
    if let Some(matched) = &case.matched {
        assert_eq!(
            finding.match_text().as_bytes(),
            matched.as_bytes(),
            "{}",
            case.name
        );
    }
    if let Some(expected) = case.secret_range {
        assert_eq!(finding.secret_range(), range(expected), "{}", case.name);
    }
    if let Some(expected) = case.match_range {
        assert_eq!(finding.match_range(), range(expected), "{}", case.name);
    }
    if let Some(position) = &case.location {
        assert_eq!(finding.location(), position.location(), "{}", case.name);
    }
}

fn assert_required(required: &Required, findings: &[Finding]) {
    let matches = for_rule(findings, &required.rule);
    let finding = matches
        .iter()
        .find(|finding| {
            finding.secret().as_bytes() == required.secret.as_bytes()
                && finding.secret_range() == range(required.secret_range)
        })
        .expect("required prior occurrence remains");
    if let Some(matched) = &required.matched {
        assert_eq!(finding.match_text().as_bytes(), matched.as_bytes());
    }
    if let Some(expected) = required.match_range {
        assert_eq!(finding.match_range(), range(expected));
    }
    if let Some(position) = &required.location {
        assert_eq!(finding.location(), position.location());
    }
}

#[test]
fn primary_formats_and_every_authored_family_case_are_executable() {
    assert_eq!(cases().primary.len(), 27);
    assert_eq!(cases().cases.len(), 491);
    assert_eq!(config().rules().len(), 476);
    assert_eq!(selected().config().rules().len(), 27);
    for case in cases().primary.iter().chain(&cases().cases) {
        let input = STANDARD.decode(&case.input_base64).unwrap();
        assert_case(case, &scan(selected(), &input, &case.path));
    }
}

#[test]
fn full_composition_separates_new_occurrences_from_extraction_and_attribution() {
    assert_eq!(
        cases()
            .primary
            .iter()
            .filter(|case| case.before_occurrence == Some(false))
            .count(),
        24
    );
    assert_eq!(
        cases()
            .primary
            .iter()
            .filter(|case| case.before_occurrence == Some(true))
            .count(),
        3
    );
    for case in &cases().primary {
        let input = STANDARD.decode(&case.input_base64).unwrap();
        let prior = scan(previous(), &input, &case.path);
        let [start, end] = case.secret_range.unwrap();
        let overlap = prior.iter().any(|finding| match finding.secret_range() {
            FindingRange::Exact(span) => span.start() < end && start < span.end(),
            FindingRange::Unavailable => false,
            _ => panic!("unexpected raw range"),
        });
        assert_eq!(overlap, case.before_occurrence.unwrap(), "{}", case.name);
        let exact = prior.iter().any(|finding| {
            finding.secret().as_bytes() == case.secret.as_ref().unwrap().as_bytes()
                && finding.secret_range() == range([start, end])
        });
        assert_eq!(exact, case.before_exact.unwrap(), "{}", case.name);
        let after = scan(composed(), &input, &case.path);
        assert_case(case, &after);
        if let Some(required) = &case.before_required {
            assert_required(required, &prior);
            assert_required(required, &after);
        }
    }
    for case in cases()
        .cases
        .iter()
        .filter(|case| case.before_required.is_some())
    {
        let input = STANDARD.decode(&case.input_base64).unwrap();
        assert_required(
            case.before_required.as_ref().unwrap(),
            &scan(previous(), &input, &case.path),
        );
        let after = scan(composed(), &input, &case.path);
        assert_required(case.before_required.as_ref().unwrap(), &after);
        assert_case(case, &after);
    }
}

#[test]
fn native_entropy_tuples_and_exact_comparator_boundaries_are_retained() {
    assert_eq!(cases().entropy.len(), 17);
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
    for (reject, threshold, count) in [
        ("lt", 2.0_f64, 1),
        ("le", 2.0_f64, 0),
        ("lt", f64::from_bits(2.0_f64.to_bits() + 1), 0),
        ("le", f64::from_bits(2.0_f64.to_bits() - 1), 1),
    ] {
        let source = format!(
            "[[rules]]\nid='rustleaks.format-entropy-control'\nregex='probe=([0-3]{{8}})'\nsecretGroup=1\nentropy={{algorithm='byte-shannon-f64-v1',reject='{reject}',threshold={threshold:?}}}\n"
        );
        let (compiled, _) = NativePolicy::builder()
            .with_pack("format-entropy-control-v1", &source)
            .unwrap()
            .compile()
            .unwrap();
        let engine = Engine::builder(
            compiled
                .select_rules(["rustleaks.format-entropy-control"])
                .unwrap(),
        )
        .build()
        .unwrap();
        assert_eq!(
            scan(&engine, b"probe=00112233", "credentials.txt").len(),
            count
        );
    }
}

fn added_rules() -> Vec<toml::Value> {
    let pack: toml::Value = toml::from_str(PROVIDER_RULES_V1).unwrap();
    pack["rules"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|rule| {
            cases()
                .primary
                .iter()
                .any(|case| Some(case.rule.as_str()) == rule["id"].as_str())
        })
        .cloned()
        .collect()
}

fn engine_with_local_allowlist(specification: &toml::Value) -> Engine {
    let mut rules = added_rules();
    for rule in &mut rules {
        rule.as_table_mut()
            .unwrap()
            .entry("allowlists")
            .or_insert_with(|| toml::Value::Array(Vec::new()))
            .as_array_mut()
            .unwrap()
            .push(specification.clone());
    }
    let mut pack = toml::Table::new();
    pack.insert("rules".into(), toml::Value::Array(rules));
    let (compiled, _) = NativePolicy::builder()
        .with_pack(
            "format-allowlist-controls-v1",
            &toml::to_string(&pack).unwrap(),
        )
        .unwrap()
        .compile()
        .unwrap();
    Engine::builder(
        compiled
            .select_rules(cases().primary.iter().map(|case| case.rule.as_str()))
            .unwrap(),
    )
    .build()
    .unwrap()
}

fn exact_pattern(text: &str) -> String {
    // Independently encode every ASCII byte as a regex literal.
    use std::fmt::Write as _;
    let mut pattern = String::from("^");
    for byte in text.bytes() {
        write!(pattern, "\\x{byte:02x}").unwrap();
    }
    pattern.push('$');
    pattern
}

#[test]
fn native_local_allowlist_targets_stopwords_commits_and_marker_controls_hold() {
    for target in ["secret", "match", "line"] {
        let mut table = toml::Table::new();
        table.insert("regexTarget".into(), toml::Value::String(target.into()));
        table.insert(
            "regexes".into(),
            toml::Value::Array(vec![toml::Value::String(".".into())]),
        );
        let engine = engine_with_local_allowlist(&toml::Value::Table(table));
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
    let mut table = toml::Table::new();
    table.insert(
        "stopwords".into(),
        toml::Value::Array(
            cases()
                .primary
                .iter()
                .map(|case| {
                    let secret = case.secret.as_ref().unwrap();
                    let middle = secret.len() / 2;
                    toml::Value::String(secret[middle..middle + 4].to_ascii_uppercase())
                })
                .collect(),
        ),
    );
    let engine = engine_with_local_allowlist(&toml::Value::Table(table));
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
    let engine = engine_with_local_allowlist(
        &toml::from_str("commits=['synthetic-format-commit']").unwrap(),
    );
    for case in &cases().primary {
        let input = STANDARD.decode(&case.input_base64).unwrap();
        for (commit, count) in [
            ("synthetic-format-commit", 0),
            ("synthetic-format-neighbor", 1),
        ] {
            let fragment = Fragment::builder(input.as_slice())
                .file_path(case.path.as_str())
                .commit(commit)
                .build();
            let outcome = engine.scan_fragment(&fragment, &ScanOptions::default());
            assert!(outcome.is_complete());
            assert_eq!(
                for_rule(outcome.findings(), &case.rule).len(),
                count,
                "{}",
                case.name
            );
        }
        let mut marked = input;
        marked.extend_from_slice(b" # rustleaks:allow");
        let fragment = Fragment::builder(marked.as_slice())
            .file_path(case.path.as_str())
            .build();
        assert!(
            selected()
                .scan_fragment(&fragment, &ScanOptions::default())
                .findings()
                .is_empty()
        );
        let enabled = selected().scan_fragment(
            &fragment,
            &ScanOptions::builder().honor_allow_markers(false).build(),
        );
        assert!(enabled.is_complete());
        assert_case(case, enabled.findings());
    }
}

#[test]
fn native_exact_match_allowlists_do_not_confuse_secret_with_context() {
    for case in &cases().primary {
        let input = STANDARD.decode(&case.input_base64).unwrap();
        for (value, count) in [
            (case.matched.as_ref().unwrap(), 0),
            (
                case.secret.as_ref().unwrap(),
                usize::from(case.match_range != case.secret_range),
            ),
        ] {
            let mut table = toml::Table::new();
            table.insert("regexTarget".into(), toml::Value::String("match".into()));
            table.insert(
                "regexes".into(),
                toml::Value::Array(vec![toml::Value::String(exact_pattern(value))]),
            );
            let engine = engine_with_local_allowlist(&toml::Value::Table(table));
            assert_eq!(
                for_rule(&scan(&engine, &input, &case.path), &case.rule).len(),
                count,
                "{}",
                case.name
            );
        }
    }
}

#[test]
fn custom_global_target_rules_and_commit_allowlists_have_positive_controls() {
    // Native packs prohibit adding global predicates. This custom-config
    // control uses the same lexical rules and local filters with entropy
    // removed, isolating global allowlist semantics. Native entropy and all
    // native primary outcomes are checked independently above.
    for case in &cases().primary {
        let mut rule = added_rules()
            .into_iter()
            .find(|rule| rule["id"].as_str() == Some(case.rule.as_str()))
            .unwrap();
        rule.as_table_mut().unwrap().remove("entropy");
        for (target, count) in [(case.rule.as_str(), 0), ("unrelated-format-control", 1)] {
            let mut pack = toml::Table::new();
            let neighbor: toml::Value =
                toml::from_str("id='unrelated-format-control'\nregex='NEVER_A_FORMAT_CREDENTIAL'")
                    .unwrap();
            pack.insert(
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
                    case.secret.as_ref().unwrap(),
                ))]),
            );
            pack.insert(
                "allowlists".into(),
                toml::Value::Array(vec![toml::Value::Table(predicate)]),
            );
            let raw: RawConfig = toml::from_str(&toml::to_string(&pack).unwrap()).unwrap();
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
        let mut pack = toml::Table::new();
        pack.insert("rules".into(), toml::Value::Array(vec![rule]));
        let predicate: toml::Value = toml::from_str("commits=['synthetic-format-commit']").unwrap();
        pack.insert("allowlists".into(), toml::Value::Array(vec![predicate]));
        let raw: RawConfig = toml::from_str(&toml::to_string(&pack).unwrap()).unwrap();
        let engine = Engine::builder(ConfigLoader::new().compile(raw).unwrap())
            .build()
            .unwrap();
        let input = STANDARD.decode(&case.input_base64).unwrap();
        for (commit, count) in [
            ("synthetic-format-commit", 0),
            ("synthetic-format-neighbor", 1),
        ] {
            let fragment = Fragment::builder(input.as_slice())
                .file_path(case.path.as_str())
                .commit(commit)
                .build();
            let outcome = engine.scan_fragment(&fragment, &ScanOptions::default());
            assert!(outcome.is_complete());
            assert_eq!(outcome.findings().len(), count, "{}", case.name);
        }
    }
}

#[test]
fn ascii_secret_fields_reject_unicode_casefold_digits_and_invalid_bytes() {
    for case in &cases().primary {
        let original = STANDARD.decode(&case.input_base64).unwrap();
        let [start, end] = case.secret_range.unwrap();
        for replacement in [
            "ſ".as_bytes(),
            "\u{212a}".as_bytes(),
            "١".as_bytes(),
            &[0xff],
        ] {
            // The exact authored capture determines the field, never a global
            // search for a possibly repeated substring elsewhere in the input.
            let index = start + (end - start) / 2;
            let mut input = original[..index].to_vec();
            input.extend_from_slice(replacement);
            input.extend_from_slice(&original[index + 1..]);
            assert!(
                for_rule(&scan(selected(), &input, &case.path), &case.rule).is_empty(),
                "{} {replacement:?}",
                case.name
            );
        }
    }
}

#[test]
fn every_format_obeys_explicit_resource_limits_and_exact_target_size() {
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
            assert!(result.findings().is_empty(), "{}", case.name);
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
    }
}

#[test]
fn repeated_formats_keep_all_exact_ranges_and_bounded_work_stops() {
    for case in &cases().primary {
        let original = STANDARD.decode(&case.input_base64).unwrap();
        let mut input = Vec::new();
        for _ in 0..128 {
            input.extend_from_slice(&original);
            input.push(b'\n');
        }
        let engine = Engine::builder(config().select_rules([case.rule.as_str()]).unwrap())
            .build()
            .unwrap();
        let all = scan(&engine, &input, &case.path);
        let findings = for_rule(&all, &case.rule);
        assert_eq!(findings.len(), 128, "{}", case.name);
        let [start, end] = case.secret_range.unwrap();
        for index in 0..128 {
            let offset = index * (original.len() + 1);
            assert!(
                findings.iter().any(|finding| finding.secret_range()
                    == range([start + offset, end + offset])
                    && finding.secret().as_bytes() == case.secret.as_ref().unwrap().as_bytes()),
                "{} {index}",
                case.name
            );
        }
        let result = engine.scan_fragment_controlled(
            &Fragment::new(input),
            &ScanOptions::default(),
            &ScanControl::unlimited().with_budget(ScanBudget::unlimited().max_work_units(1)),
        );
        assert!(!result.is_complete(), "{}", case.name);
    }
}

fn repeated(length: usize) -> String {
    "H7q2M9v4R1x8B5n3T6z0DkWcYpSgJfUa"
        .chars()
        .cycle()
        .take(length)
        .collect()
}

#[test]
fn unbounded_gitlab_tokens_and_hcp_whitespace_keep_exact_bytes_and_limits() {
    for length in [8_192, 262_144] {
        let token = repeated(length);
        let prefix = "incoming+project-123-";
        let input = format!("{prefix}{token}-issue@");
        let hcp_secret = cases()
            .primary
            .iter()
            .find(|case| case.rule == "rustleaks.hcp-client-secret")
            .unwrap()
            .secret
            .as_ref()
            .unwrap();
        let hcp_prefix = format!(
            "HCP_CLIENT_SECRET{}=",
            " \t\r\x0c".chars().cycle().take(length).collect::<String>()
        );
        let hcp = format!("{hcp_prefix}{hcp_secret},");
        for (rule, input, secret, start) in [
            (
                "rustleaks.gitlab-incoming-mail-address-token",
                input.as_str(),
                token.as_str(),
                prefix.len(),
            ),
            (
                "rustleaks.hcp-client-secret",
                hcp.as_str(),
                hcp_secret.as_str(),
                hcp_prefix.len(),
            ),
        ] {
            let engine = Engine::builder(config().select_rules([rule]).unwrap())
                .build()
                .unwrap();
            let findings = scan(&engine, input.as_bytes(), "credentials.txt");
            assert_eq!(findings.len(), 1, "{rule} {length}");
            assert_eq!(findings[0].secret().as_bytes(), secret.as_bytes());
            assert_eq!(
                findings[0].secret_range(),
                range([start, start + secret.len()])
            );
            let fragment = Fragment::new(input.as_bytes());
            for budget in [
                ScanBudget::unlimited().max_finding_payload_bytes(1_024),
                ScanBudget::unlimited().max_work_units(0),
            ] {
                let result = engine.scan_fragment_controlled(
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
fn base64_and_nested_base64_preserve_source_projection_and_exact_decoded_secrets() {
    for case in &cases().primary {
        let original = STANDARD.decode(&case.input_base64).unwrap();
        for depth in [1, 2] {
            let mut encoded = original.clone();
            for _ in 0..depth {
                encoded = STANDARD.encode(encoded).into_bytes();
            }
            let fragment = Fragment::builder(encoded.as_slice())
                .file_path(case.path.as_str())
                .build();
            let outcome = selected().scan_fragment(
                &fragment,
                &ScanOptions::builder().max_decode_depth(depth).build(),
            );
            assert!(outcome.is_complete());
            let findings = for_rule(outcome.findings(), &case.rule);
            assert_eq!(findings.len(), 1, "{} depth {depth}", case.name);
            assert_eq!(
                findings[0].secret().as_bytes(),
                case.secret.as_ref().unwrap().as_bytes()
            );
            assert_eq!(
                findings[0].match_text().as_bytes(),
                case.matched.as_ref().unwrap().as_bytes()
            );
            assert_eq!(findings[0].secret_range(), FindingRange::Unavailable);
            assert_eq!(findings[0].match_range(), FindingRange::Unavailable);
            assert_eq!(
                findings[0].location(),
                Location::new(0, 0, 1, encoded.len()).unwrap()
            );
            let shallow = selected().scan_fragment(
                &fragment,
                &ScanOptions::builder().max_decode_depth(depth - 1).build(),
            );
            assert!(shallow.is_complete());
            assert!(for_rule(shallow.findings(), &case.rule).is_empty());
        }
    }
}

#[test]
fn one_composed_engine_keeps_concurrent_primary_and_negative_contracts() {
    std::thread::scope(|scope| {
        for _ in 0..4 {
            scope.spawn(|| {
                for _ in 0..16 {
                    for case in cases()
                        .primary
                        .iter()
                        .chain(cases().cases.iter().filter(|case| case.count == 0))
                    {
                        assert_case(
                            case,
                            &scan(
                                composed(),
                                &STANDARD.decode(&case.input_base64).unwrap(),
                                &case.path,
                            ),
                        );
                    }
                }
            });
        }
    });
}

#[test]
fn source_context_case_whitespace_and_numeric_fields_remain_ascii() {
    for (id, label) in [
        ("rustleaks.datadog-api-key", "datadog"),
        ("rustleaks.datadog-application-key-delimiter", "datadog"),
        ("rustleaks.etsy-open-api-key", "etsy"),
        ("rustleaks.gocardless-api-token-delimiter", "gocardless"),
        ("rustleaks.monday-api-token", "monday"),
    ] {
        let case = cases().primary.iter().find(|case| case.rule == id).unwrap();
        let secret = case.secret.as_ref().unwrap();
        let original = STANDARD.decode(&case.input_base64).unwrap();
        let suffix = std::str::from_utf8(&original[case.secret_range.unwrap()[1]..]).unwrap();
        for whitespace in [" ", "\t", "\n", "\r", "\x0b", "\x0c"] {
            let input = format!(
                "{}={whitespace}{secret}{suffix}",
                label.to_ascii_uppercase()
            );
            assert_eq!(
                for_rule(&scan(selected(), input.as_bytes(), &case.path), id).len(),
                1,
                "{id} {whitespace:?}"
            );
        }
        let input = format!("{label}=\u{a0}{secret}{suffix}");
        assert!(
            for_rule(&scan(selected(), input.as_bytes(), &case.path), id).is_empty(),
            "{id}"
        );
        for (index, byte) in label.bytes().enumerate().filter(|(_, byte)| *byte == b's') {
            assert_eq!(byte, b's');
            let input = format!(
                "{}ſ{} = {secret}{suffix}",
                &label[..index],
                &label[index + 1..]
            );
            assert!(
                for_rule(&scan(selected(), input.as_bytes(), &case.path), id).is_empty(),
                "{id}"
            );
        }
    }
    let case = cases()
        .primary
        .iter()
        .find(|case| case.rule == "rustleaks.hcp-client-secret")
        .unwrap();
    let secret = case.secret.as_ref().unwrap();
    for label in ["HCP_CLIENT_SECRET", "hcp_client_secret"] {
        for whitespace in [" ", "\t", "\n", "\r", "\x0c"] {
            let input = format!("{label}{whitespace}={whitespace}{secret},");
            assert_eq!(
                for_rule(&scan(selected(), input.as_bytes(), &case.path), &case.rule).len(),
                1
            );
        }
        for whitespace in ["\x0b", "\u{a0}"] {
            let input = format!("{label}{whitespace}={secret},");
            assert!(
                for_rule(&scan(selected(), input.as_bytes(), &case.path), &case.rule).is_empty()
            );
        }
    }
    for (id, input) in [
        (
            "rustleaks.databricks-api-token-delimiter",
            format!("dapi{}-١\\\"", "a7f2b9e4c1d80563".repeat(2)),
        ),
        (
            "rustleaks.gitlab-incoming-mail-address-token",
            format!("incoming+project-١23-{}-issue@", repeated(20)),
        ),
        (
            "rustleaks.slack-config-refresh-token-147",
            format!("xoxe-١-{};", repeated(147)),
        ),
    ] {
        assert!(
            for_rule(&scan(selected(), input.as_bytes(), "credentials.txt"), id).is_empty(),
            "{id}"
        );
    }
}

#[test]
fn ordinary_grafana_attribution_and_existing_specific_findings_remain_visible() {
    let secret = format!("eyJrIjoi{}", repeated(80));
    let input = format!("xx {secret};");
    let expected = [3, 3 + secret.len()];
    for engine in [previous(), composed()] {
        let all = scan(engine, input.as_bytes(), "credentials.txt");
        let prior = for_rule(&all, "grafana-api-key");
        assert_eq!(prior.len(), 1);
        assert_eq!(prior[0].secret().as_bytes(), secret.as_bytes());
        assert_eq!(prior[0].secret_range(), range(expected));
    }
    let all = scan(composed(), input.as_bytes(), "credentials.txt");
    let added = for_rule(&all, "rustleaks.grafana-api-key-base64");
    assert_eq!(added.len(), 1);
    assert_eq!(added[0].secret().as_bytes(), secret.as_bytes());
    assert_eq!(added[0].secret_range(), range(expected));
}

#[test]
fn rule_selection_retains_source_keywords_and_standalone_secret_roles() {
    for contract in &cases().contracts {
        let id = contract.rule.as_str();
        let expected: Vec<_> = contract
            .keywords
            .iter()
            .map(|word| word.to_ascii_lowercase())
            .collect();
        assert_eq!(selected().config().rule(id).unwrap().keywords(), expected);
        assert!(
            selected()
                .config()
                .rule(id)
                .unwrap()
                .required_rules()
                .is_empty()
        );
        // Keyword-only context must not manufacture a credential finding.
        let input = expected.join(" ");
        assert!(for_rule(&scan(selected(), input.as_bytes(), "credentials.txt"), id).is_empty());
    }
}
