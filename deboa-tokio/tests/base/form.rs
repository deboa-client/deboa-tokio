use deboa::TestResult;

#[test]
fn test_encoded_form() -> TestResult<()> {
    deboa_test_utils::base::form::test_encoded_form()
}
