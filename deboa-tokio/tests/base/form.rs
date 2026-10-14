use deboa::TestResult;
use deboa_tokio::Client;
use easyhttpmock_vetis_tokio::{vetis_adapter::VetisAdapter, EasyHttpMock};
use rstest::rstest;

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
