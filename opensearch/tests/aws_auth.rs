/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

#![cfg(feature = "aws-auth")]

pub mod common;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use aws_credential_types::{
    provider::{future, ProvideCredentials},
    Credentials as AwsCredentials,
};
use aws_smithy_async::time::StaticTimeSource;
use aws_types::region::Region;
use common::{server::MockServer, tracing_init};
use opensearch::{
    aws::AwsSigV4,
    auth::cache::CachedCredentialsProvider,
    http::headers::HOST,
    indices::IndicesCreateParts,
};
use reqwest::header::HeaderValue;
use serde_json::json;
use test_case::test_case;

#[derive(Debug)]
struct CountingCredentialsProvider {
    calls: Arc<AtomicUsize>,
}

impl CountingCredentialsProvider {
    fn new() -> (Self, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        (
            Self {
                calls: Arc::clone(&calls),
            },
            calls,
        )
    }
}

impl ProvideCredentials for CountingCredentialsProvider {
    fn provide_credentials<'a>(&'a self) -> future::ProvideCredentials<'a>
    where
        Self: 'a,
    {
        future::ProvideCredentials::new(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(AwsCredentials::new(
                "test-access-key",
                "test-secret-key",
                None,
                None,
                "test",
            ))
        })
    }
}

const LOCALHOST: HeaderValue = HeaderValue::from_static("localhost");

fn sigv4(service_name: &str, ignored_headers: &[&'static str]) -> AwsSigV4 {
    let creds = AwsCredentials::new("test-access-key", "test-secret-key", None, None, "test");

    sigv4_with_provider(creds, service_name, ignored_headers)
}

fn sigv4_cached(service_name: &str, ignored_headers: &[&'static str]) -> AwsSigV4 {
    let creds = AwsCredentials::new("test-access-key", "test-secret-key", None, None, "test");
    let cached = CachedCredentialsProvider::new(creds);

    sigv4_with_provider(cached, service_name, ignored_headers)
}

fn sigv4_with_provider(
    credentials_provider: impl ProvideCredentials + 'static,
    service_name: &str,
    ignored_headers: &[&'static str],
) -> AwsSigV4 {
    let builder = AwsSigV4::builder()
        .credentials_provider(credentials_provider)
        .region(Region::new("ap-southeast-2"))
        .service_name(service_name.to_owned())
        .time_source(StaticTimeSource::from_secs(1673626117)); // 2023-01-13 16:08:37 +0000

    let builder = ignored_headers
        .into_iter()
        .fold(builder, |builder, &header| builder.ignore_header(header));

    builder.build().expect("sigv4 config should be valid")
}

#[test_case("es", "10c9be415f4b9f15b12abbb16bd3e3730b2e6c76e0cf40db75d08a44ed04a3a1"; "when service name is es")]
#[test_case("aoss", "34903aef90423aa7dd60575d3d45316c6ef2d57bbe564a152b41bf8f5917abf6"; "when service name is aoss")]
#[test_case("arbitrary", "156e65c504ea2b2722a481b7515062e7692d27217b477828854e715f507e6a36"; "when service name is arbitrary")]
#[tokio::test]
async fn aws_auth_signs_correctly(
    service_name: &str,
    expected_signature: &str,
) -> anyhow::Result<()> {
    tracing_init();

    let mut server = MockServer::start()?;

    let host = format!("aaabbbcccddd111222333.ap-southeast-2.{service_name}.amazonaws.com");

    let client = server.client_with(|b| {
        b.aws_sigv4(sigv4(service_name, &[]))
            .header(HOST, host.parse().unwrap())
    });

    let _ = client
        .indices()
        .create(IndicesCreateParts::Index("sample-index1"))
        .body(json!({
            "aliases": {
                "sample-alias1": {}
            },
            "mappings": {
                "properties": {
                    "age": {
                        "type": "integer"
                    }
                }
            },
            "settings": {
                "index.number_of_replicas": 1,
                "index.number_of_shards": 2
            }
        }))
        .send()
        .await?;

    let sent_req = server.received_request().await?;

    assert_eq!(sent_req.header("accept"), Some("application/json"));
    assert_eq!(sent_req.header("content-type"), Some("application/json"));
    assert_eq!(sent_req.header("host"), Some(host.as_str()));
    assert_eq!(sent_req.header("x-amz-date"), Some("20230113T160837Z"));
    assert_eq!(
        sent_req.header("x-amz-content-sha256"),
        Some("4c770eaed349122a28302ff73d34437cad600acda5a9dd373efc7da2910f8564")
    );
    assert_eq!(sent_req.header("authorization"), Some(format!("AWS4-HMAC-SHA256 Credential=test-access-key/20230113/ap-southeast-2/{service_name}/aws4_request, SignedHeaders=accept;content-type;host;x-amz-content-sha256;x-amz-date, Signature={expected_signature}").as_str()));

    Ok(())
}

#[tokio::test]
async fn aws_auth_get() -> anyhow::Result<()> {
    tracing_init();

    let mut server = MockServer::start()?;
    let client = server.client_with(|b| b.aws_sigv4(sigv4("custom", &["host"])));

    let _ = client.ping().send().await?;

    let sent_req = server.received_request().await?;

    assert_eq!(sent_req.header("authorization"), Some("AWS4-HMAC-SHA256 Credential=test-access-key/20230113/ap-southeast-2/custom/aws4_request, SignedHeaders=accept;content-type;x-amz-content-sha256;x-amz-date, Signature=8c882ad6cff05cb6c5bc91a030a92582787f34ef4af858a728c6f943c4ff2f21"));
    assert_eq!(
        sent_req.header("x-amz-content-sha256"),
        Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    ); // SHA of zero-length body

    Ok(())
}

#[tokio::test]
async fn aws_auth_through_cached_provider_produces_identical_signature() -> anyhow::Result<()> {
    // Same fixture as `aws_auth_get`; wrapping with CachedCredentialsProvider must not
    // change the signature.
    tracing_init();

    let mut server = MockServer::start()?;

    let client = server.client_with(|b| {
        b.aws_sigv4(sigv4_cached("custom", &[]))
            .header(HOST, LOCALHOST)
    });

    let _ = client.ping().send().await?;

    let sent_req = server.received_request().await?;

    assert_eq!(sent_req.header("authorization"), Some("AWS4-HMAC-SHA256 Credential=test-access-key/20230113/ap-southeast-2/custom/aws4_request, SignedHeaders=accept;content-type;host;x-amz-content-sha256;x-amz-date, Signature=e5aa6e5d9e1b86b86ed31fbb10dd62b4e93423b77830f8189701421d3e9f65bd"));
    assert_eq!(
        sent_req.header("x-amz-content-sha256"),
        Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    ); // SHA of zero-length body

    Ok(())
}

#[tokio::test]
async fn cached_provider_reuses_credentials_across_requests() -> anyhow::Result<()> {
    tracing_init();

    let mut server = MockServer::start()?;
    let (provider, calls) = CountingCredentialsProvider::new();
    let cached = CachedCredentialsProvider::new(provider);
    let sigv4 = sigv4_with_provider(cached, "custom", &[]);
    let client = server.client_with(|b| b.aws_sigv4(sigv4).header(HOST, LOCALHOST));

    let _ = client.ping().send().await?;
    let _ = client.ping().send().await?;

    let _ = server.received_request().await?;
    let _ = server.received_request().await?;

    assert_eq!(calls.load(Ordering::SeqCst), 1);

    Ok(())
}

#[tokio::test]
async fn aws_auth_post() -> anyhow::Result<()> {
    tracing_init();

    let mut server = MockServer::start()?;

    let client = server.client_with(|b| b.aws_sigv4(sigv4("custom", &[])));

    let _ = client
        .index(opensearch::IndexParts::Index("movies"))
        .body(serde_json::json!({
                "title": "Moneyball",
                "director": "Bennett Miller",
                "year": 2011
            }
        ))
        .send()
        .await?;

    let sent_req = server.received_request().await?;

    assert_eq!(
        sent_req.header("x-amz-content-sha256"),
        Some("f3a842f988a653a734ebe4e57c45f19293a002241a72f0b3abbff71e4f5297b9")
    ); // SHA of the JSON

    Ok(())
}
