use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::tempdir;

fn bin() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("keynest"))
}

#[test]
fn init_creates_store_file() {
    let dir = tempdir().unwrap();
    let store = dir.path().join("test.db");

    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .arg("init")
        .assert()
        .success()
        .stdout(predicate::str::contains("keystore initialized"));

    assert!(store.exists());
}

#[test]
fn set_and_get_roundtrip() {
    let dir = tempdir().unwrap();
    let store = dir.path().join("test.db");

    // init
    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .arg("init")
        .assert()
        .success();

    // set
    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .arg("set")
        .arg("A")
        .arg("B")
        .assert()
        .success()
        .stdout(predicate::str::contains("stored secret"));

    // get
    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .arg("get")
        .arg("A")
        .assert()
        .success()
        .stdout(predicate::str::contains("B"));
}

#[test]
fn set_existing_key_twice_fails() {
    let dir = tempdir().unwrap();
    let store = dir.path().join("test.db");

    // init
    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .arg("init")
        .assert()
        .success();

    // set
    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .arg("set")
        .arg("A")
        .arg("B")
        .assert()
        .success();

    // set second time
    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .arg("set")
        .arg("A")
        .arg("C")
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));
}

#[test]
fn wrong_password_fails() {
    let dir = tempdir().unwrap();
    let store = dir.path().join("test.db");

    // init
    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .arg("init")
        .assert()
        .success();

    // get
    bin()
        .env("KEYNEST_PASSWORD", "wrong_pw")
        .arg("--store")
        .arg(&store)
        .arg("get")
        .arg("A")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "Invalid password or corrupted data",
        ));
}

#[test]
fn init_fails_if_store_exists() {
    let dir = tempdir().unwrap();
    let store = dir.path().join("test.db");

    // init
    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .arg("init")
        .assert()
        .success();

    // second init
    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .arg("init")
        .assert()
        .failure()
        .stderr(predicate::str::contains("keynest store already exists"));
}

#[test]
fn actions_fail_if_store_not_exists() {
    let dir = tempdir().unwrap();
    let store = dir.path().join("test.db");

    // get
    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .arg("get")
        .arg("A")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "store does not exist",
        ));
}

#[test]
fn remove_secret_works() {
    let dir = tempdir().unwrap();
    let store = dir.path().join("test.db");

    // init
    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .arg("init")
        .assert()
        .success();

    // set
    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .arg("set")
        .arg("A")
        .arg("B")
        .assert()
        .success();

    // remove
    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .arg("remove")
        .arg("A")
        .assert()
        .success()
        .stdout(predicate::str::contains("removed successfully"));

    // get should not find key
    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .arg("get")
        .arg("A")
        .assert()
        .success()
        .stdout(predicate::str::contains("not found"));
}

#[test]
fn init_with_custom_argon2_parameters() {
    let dir = tempdir().unwrap();
    let store = dir.path().join("test.db");

    // init
    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .arg("init")
        .arg("--argon-mem")
        .arg("32768")
        .arg("--argon-time")
        .arg("2")
        .arg("--argon-parallelism")
        .arg("1")
        .assert()
        .success();
}

#[test]
fn init_with_incomplete_argon2_parameters() {
    let dir = tempdir().unwrap();
    let store = dir.path().join("test.db");

    // init
    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .arg("init")
        .arg("--argon-mem")
        .arg("32768")
        .arg("--argon-time")
        .arg("2")
        .assert()
        .success();
}
