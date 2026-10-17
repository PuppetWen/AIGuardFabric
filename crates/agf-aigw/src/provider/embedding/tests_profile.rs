use super::test_server::{KEY, configuration};
use super::{EmbeddingClient, EmbeddingFailure, EmbeddingProfile, wire::ValidatedEmbedding};

#[test]
fn production_profile_requires_unambiguous_https_origin_and_fixed_revision() {
    let valid = configuration("https://embedding.example.test".into());
    assert!(EmbeddingProfile::from_server_configuration(valid.clone()).is_ok());
    for origin in [
        "http://127.0.0.1:9000",
        "https://user:secret@embedding.example.test",
        "https://embedding.example.test/v1",
        "https://embedding.example.test?",
        "https://embedding.example.test#",
        " https://embedding.example.test",
        "https://embedding.example.test\\evil",
        "https://embedding.example.test/%2f",
        "https://embedding.example.test/./",
        "https://embedding.example.test/path/..",
    ] {
        let mut config = valid.clone();
        config.origin = origin.into();
        assert!(matches!(EmbeddingProfile::from_server_configuration(config), Err(EmbeddingFailure::Configuration)));
    }
    let mut config = valid;
    config.model_revision.clear();
    assert!(matches!(EmbeddingProfile::from_server_configuration(config), Err(EmbeddingFailure::Configuration)));
}

#[test]
fn test_constructor_accepts_only_explicit_literal_loopback_port() {
    assert!(EmbeddingProfile::literal_loopback_for_test(configuration("http://127.0.0.1:9000".into())).is_ok());
    for origin in [
        "http://localhost:9000",
        "http://0.0.0.0:9000",
        "http://2130706433:9000",
        "http://127.1:9000",
        "http://127.0.0.1",
        "http://127.0.0.1:0",
        "http://127.0.0.2:9000",
        "https://127.0.0.1:9000",
    ] {
        assert!(matches!(
            EmbeddingProfile::literal_loopback_for_test(configuration(origin.into())),
            Err(EmbeddingFailure::Configuration)
        ));
    }
}

#[test]
fn dimensions_price_and_service_generation_are_bounded() {
    let mut config = configuration("https://embedding.example.test".into());
    for dimension in [0, 4097, u16::MAX] {
        config.dimensions = dimension;
        assert!(matches!(
            EmbeddingProfile::from_server_configuration(config.clone()),
            Err(EmbeddingFailure::Configuration)
        ));
    }
    config.dimensions = 4096;
    assert!(EmbeddingProfile::from_server_configuration(config.clone()).is_ok());
    config.configuration_version = 0;
    assert!(EmbeddingProfile::from_server_configuration(config.clone()).is_err());
    config.configuration_version = 1;
    config.input_micro_per_1k = u64::MAX;
    assert!(EmbeddingProfile::from_server_configuration(config).is_err());
}

#[test]
fn configured_price_rounds_up_independently_and_never_truncates_reported_tokens() {
    let profile =
        EmbeddingProfile::from_server_configuration(configuration("https://embedding.example.test".into())).unwrap();
    assert_eq!(profile.cost_for(1), 1);
    assert_eq!(profile.cost_for(19), 10);
    assert_eq!(profile.cost_for(1_000_001), 500_001);
    let mut config = configuration("https://embedding.example.test".into());
    config.input_micro_per_1k = 0;
    // A configured price of zero is not evidence that an external provider billed nothing.
    assert_eq!(EmbeddingProfile::from_server_configuration(config).unwrap().cost_for(19), 0);
}

#[test]
fn credentials_and_vector_debug_do_not_expose_secret_or_values() {
    let profile =
        EmbeddingProfile::from_server_configuration(configuration("https://embedding.example.test".into())).unwrap();
    for key in ["", " secret", "secret\nheader", "secret key", "秘密"] {
        assert!(matches!(
            EmbeddingClient::from_service_profile(profile.clone(), key),
            Err(EmbeddingFailure::Credentials)
        ));
    }
    let client = EmbeddingClient::from_service_profile(profile, KEY).unwrap();
    assert!(!format!("{client:?}").contains(KEY));
    let vector = ValidatedEmbedding::new(vec![0.125, 0.25, -0.5], 3).unwrap();
    assert!(!format!("{vector:?}").contains("0.125"));
    for values in [vec![0.0; 3], vec![f32::NAN, 1.0, 0.0], vec![f32::INFINITY, 1.0, 0.0], vec![1.0]] {
        assert!(ValidatedEmbedding::new(values, 3).is_err());
    }
}
