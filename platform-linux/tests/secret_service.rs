//! `SecretServiceStore` against a running Secret Service: oo7-daemon served
//! in-process over a peer-to-peer D-Bus connection, its default collection
//! unlocked with the test keyring secret and its prompts answered by the
//! daemon's mock GNOME prompter.
#![cfg(target_os = "linux")]

use core_types::{CredentialError, CredentialId, CredentialStore};
use oo7_daemon::tests::TestServiceSetup;
use platform_linux::keyring::SecretServiceStore;

fn id(account: &str) -> CredentialId {
    CredentialId {
        service: "open-sesame-test".into(),
        account: account.into(),
    }
}

async fn service() -> (TestServiceSetup, SecretServiceStore) {
    let setup = TestServiceSetup::plain_session(true).await.unwrap();
    let store = SecretServiceStore::with_connection(&setup.client_conn)
        .await
        .unwrap();
    (setup, store)
}

#[tokio::test]
async fn credentials_round_trip_replace_and_delete() {
    let (_setup, store) = service().await;
    let kek = id("vault-kek:work");
    assert!(store.get(&kek).await.unwrap().is_none());

    store.set(&kek, "test key", &[1; 32]).await.unwrap();
    assert_eq!(store.get(&kek).await.unwrap().unwrap().as_bytes(), &[1; 32]);

    store.set(&kek, "test key", &[2; 32]).await.unwrap();
    assert_eq!(
        store.get(&kek).await.unwrap().unwrap().as_bytes(),
        &[2; 32],
        "set replaces the credential instead of adding a second"
    );
    assert!(
        store.get(&id("vault-kek:home")).await.unwrap().is_none(),
        "credentials are told apart by account"
    );

    assert!(store.delete(&kek).await.unwrap());
    assert!(store.get(&kek).await.unwrap().is_none());
    assert!(!store.delete(&kek).await.unwrap());
}

#[tokio::test]
async fn items_the_store_did_not_write_are_ambiguous_not_guessed_between() {
    let (setup, store) = service().await;
    let kek = id("vault-kek:work");
    let collection = oo7::dbus::Service::plain_with_connection(&setup.client_conn)
        .await
        .unwrap()
        .default_collection()
        .await
        .unwrap();
    let attributes = [
        ("service", kek.service.as_str()),
        ("username", kek.account.as_str()),
    ];
    for label in ["first", "second"] {
        collection
            .create_item(label, &attributes, oo7::Secret::blob([3; 32]), false, None)
            .await
            .unwrap();
    }
    assert!(matches!(
        store.get(&kek).await,
        Err(CredentialError::Ambiguous { count: 2, .. })
    ));
    assert!(matches!(
        store.set(&kek, "test key", &[4; 32]).await,
        Err(CredentialError::Ambiguous { count: 2, .. })
    ));
}

#[tokio::test]
async fn a_locked_collection_is_unlocked_not_read_as_empty() {
    let (setup, store) = service().await;
    let kek = id("vault-kek:work");
    store.set(&kek, "test key", &[5; 32]).await.unwrap();

    let default = setup.collections[0].inner().path().to_owned();
    setup.service_api.lock(&[&default], None).await.unwrap();
    assert!(setup.collections[0].is_locked().await.unwrap());

    assert_eq!(
        store.get(&kek).await.unwrap().unwrap().as_bytes(),
        &[5; 32],
        "the locked collection is unlocked before it is searched"
    );
}
