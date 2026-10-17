use caramelo::{expect, matchers::eq};
use deboa::{TestResult, form::EncodedForm, request::DeboaRequest};
use deboa_multipart::MultiPartForm;
use deboa_tokio::{Client, HttpBody};
use easyhttpmock_vetis_tokio::{
    EasyHttpMock,
    matchers::{header_value, method, path},
    mock::{AsyncMatcherExt, Mock, StatusCodeExt as _, given},
    vetis_adapter::VetisAdapter,
};
use http::{Method, StatusCode, header::CONTENT_TYPE};
use rstest::rstest;
use tokio::fs::File;

use crate::common::helpers::{create_client, create_server, protocol_version};

#[test]
fn test_encoded_form() -> TestResult<()> {
    deboa_test_utils::base::form::test_encoded_form()
}

#[rstest]
#[tokio::test]
async fn test_submit_encoded_form(
    create_client: Client,
    #[future] create_server: EasyHttpMock<VetisAdapter>,
    protocol_version: http::Version,
) -> TestResult<()> {
    let mut server = create_server.await;
    deboa_test_utils::base::form::test_submit_encoded_form(
        &create_client,
        &mut server,
        protocol_version,
    )
    .await
}

#[rstest]
#[tokio::test]
async fn test_submit_multipart_form(
    create_client: Client,
    #[future] create_server: EasyHttpMock<VetisAdapter>,
    protocol_version: http::Version,
) -> TestResult<()> {
    let mut server = create_server.await;
    let mock = Mock::of(
        given(
            method(Method::POST)
                .and(header_value(CONTENT_TYPE, "application/x-www-form-urlencoded"))
                .and(path("/posts")),
        )
        .will_return(
            StatusCode::OK
                .respond()
                .no_body(),
        ),
    );

    server
        .register_mock(mock)
        .await?;

    let form = EncodedForm::builder()
        .field("name", "deboa")
        .field("version", "0.0.1");

    let response = DeboaRequest::post(server.url("/posts"))?
        .header(CONTENT_TYPE, form.content_type())?
        .version(protocol_version)
        .bytes(&form.build())
        .send_with(&create_client)
        .await?;

    expect(response.status()).to_be(eq(StatusCode::OK));

    server
        .stop()
        .await?;

    Ok(())
}

#[rstest]
#[tokio::test]
async fn test_submit_multipart_form_file(
    create_client: Client,
    #[future] create_server: EasyHttpMock<VetisAdapter>,
    protocol_version: http::Version,
) -> TestResult<()> {
    let mut server = create_server.await;
    let file = File::open("file.txt").await?;
    let stream = tokio_util::io::ReaderStream::new(file);

    let mock = Mock::of(
        given(
            method(Method::POST)
                .and(header_value(CONTENT_TYPE, "multipart/form-data"))
                .and(path("/posts")),
        )
        .will_return(
            StatusCode::OK
                .respond()
                .no_body(),
        ),
    );

    server
        .register_mock(mock)
        .await?;

    let form = MultiPartForm::builder()
        .field("name", "deboa")
        .field("version", "0.0.1")
        .stream("file", "file.txt", "text/plain", stream);

    let response = DeboaRequest::post(server.url("/posts"))?
        .header(CONTENT_TYPE, &form.content_type())?
        .version(protocol_version)
        .body(HttpBody::stream(form.build().await))
        .send_with(&create_client)
        .await?;

    expect(response.status()).to_be(eq(StatusCode::OK));

    server
        .stop()
        .await?;

    Ok(())
}
