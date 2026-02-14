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
        .args(["set", "A", "B"])
        .assert()
        .success()
        .stdout(predicate::str::contains("stored secret"));

    // get
    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .args(["get", "A"])
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
        .args(["set", "A", "B"])
        .assert()
        .success();

    // set second time
    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .args(["set", "A", "C"])
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
        .args(["get", "A"])
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
        .args(["get", "A"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("store does not exist"));
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
        .args(["set", "A", "B"])
        .assert()
        .success();

    // remove
    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .args(["remove", "A"])
        .assert()
        .success()
        .stdout(predicate::str::contains("removed successfully"));

    // get should not find key
    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .args(["get", "A"])
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
        .args([
            "init",
            "--argon-mem",
            "32768",
            "--argon-time",
            "2",
            "--argon-parallelism",
            "1",
        ])
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
        .args(["init", "--argon-mem", "32768", "--argon-time", "2"])
        .assert()
        .success();
}

#[test]
fn rekey_to_change_pw_works() {
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

    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .args(["set", "A", "B"])
        .assert()
        .success();

    // rekey
    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .arg("rekey")
        .write_stdin("newpw\nnewpw\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("successfully"));

    //old password should not work
    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .args(["get", "A"])
        .assert()
        .failure();

    // new password should work
    bin()
        .env("KEYNEST_PASSWORD", "newpw")
        .arg("--store")
        .arg(&store)
        .args(["get", "A"])
        .assert()
        .success()
        .stdout(predicate::str::contains("B"));
}

#[test]
fn rekey_only_changes_kdf_password_stays_valid() {
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

    // rekey with stronger KDF
    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .args(["rekey", "--argon-mem", "131072"])
        .write_stdin("pw\npw\n")
        .assert()
        .success();

    // password still works
    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .arg("info")
        .assert()
        .success();
}

#[test]
fn rekey_updates_argon2_parameters() {
    let dir = tempdir().unwrap();
    let store = dir.path().join("test.db");

    // init with default
    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .arg("init")
        .assert()
        .success();

    // rekey with new memory cost
    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .arg("rekey")
        .arg("--argon-mem")
        .arg("131072")
        .write_stdin("pw\npw\n")
        .assert()
        .success();

    // check info
    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .arg("info")
        .assert()
        .success()
        .stdout(predicate::str::contains("131072"));
}

#[test]
fn rekey_fails_if_password_confirmation_mismatch() {
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

    // mismatch
    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .arg("rekey")
        .write_stdin("newpw\nwrongpw\n")
        .assert()
        .failure();
}
