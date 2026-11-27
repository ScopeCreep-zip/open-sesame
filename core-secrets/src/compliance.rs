//! Compliance test suite for `SecretsStore` implementations.
//!
//! Every backend (`InMemoryStore`, `SqlCipherStore`) must pass these tests
//! to ensure consistent behavior across platforms.

use crate::SecretsStore;

/// Run the full compliance test suite against any `SecretsStore`
/// implementation: set/get, overwrite, delete, delete-nonexistent,
/// `list_keys`, cleanup.
pub(crate) async fn compliance_tests(store: &dyn SecretsStore) {
    // -- Set and get --
    store.set("test/key1", b"value1").await.unwrap();
    let val = store.get("test/key1").await.unwrap();
    assert_eq!(val.as_bytes(), b"value1");

    // -- Overwrite --
    store.set("test/key1", b"value2").await.unwrap();
    let val = store.get("test/key1").await.unwrap();
    assert_eq!(val.as_bytes(), b"value2");

    // -- Get nonexistent --
    let result = store.get("test/nonexistent").await;
    assert!(result.is_err());

    // -- Delete --
    store.delete("test/key1").await.unwrap();
    assert!(store.get("test/key1").await.is_err());

    // -- Delete nonexistent --
    assert!(store.delete("test/key1").await.is_err());

    // -- List keys --
    store.set("test/a", b"1").await.unwrap();
    store.set("test/b", b"2").await.unwrap();
    let mut keys = store.list_keys().await.unwrap();
    keys.sort();
    assert_eq!(keys, ["test/a", "test/b"]);

    // -- Cleanup --
    store.delete("test/a").await.unwrap();
    store.delete("test/b").await.unwrap();
    let keys = store.list_keys().await.unwrap();
    assert!(keys.is_empty());
}

#[tokio::test]
async fn in_memory_store_passes_compliance() {
    compliance_tests(&crate::store::InMemoryStore::default()).await;
}
