use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::tempdir;

fn bin() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("keynest"))
}

fn is_valid_json() -> impl predicates::Predicate<str> {
    predicate::function(|s: &str| serde_json::from_str::<serde_json::Value>(s).is_ok())
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
        .stderr(predicate::str::contains("keystore already exists"));
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
        .stdout(predicate::str::contains("Removed"));

    // get should not find key
    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .args(["get", "A"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
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

#[test]
fn set_with_file() {
    let dir = tempdir().unwrap();
    let store = dir.path().join("test.db");
    let secret_file = dir.path().join("secret.txt");

    std::fs::write(&secret_file, "secret_from_file").unwrap();

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
        .args(["set", "mykey", "--file"])
        .arg(&secret_file)
        .assert()
        .success()
        .stdout(predicate::str::contains("stored secret"));

    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .args(["get", "mykey"])
        .assert()
        .success()
        .stdout(predicate::str::contains("secret_from_file"));
}

#[test]
fn set_missing_value_fails() {
    let dir = tempdir().unwrap();
    let store = dir.path().join("test.db");

    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .arg("init")
        .assert()
        .success();

    // Missing value without --prompt or --file should fail
    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .args(["set", "mykey"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("secret value required"));
}

#[test]
fn get_json_output() {
    let dir = tempdir().unwrap();
    let store = dir.path().join("test.db");

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
        .args(["set", "mykey", "myvalue"])
        .assert()
        .success();

    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .args(["get", "mykey", "--json"])
        .assert()
        .success()
        .stdout(is_valid_json())
        .stdout(predicate::str::contains("mykey"))
        .stdout(predicate::str::contains("myvalue"));
}

#[test]
fn list_json_output() {
    let dir = tempdir().unwrap();
    let store = dir.path().join("test.db");

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
        .args(["set", "key1", "val1"])
        .assert()
        .success();

    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .args(["set", "key2", "val2"])
        .assert()
        .success();

    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .args(["list", "--json"])
        .assert()
        .success()
        .stdout(is_valid_json())
        .stdout(predicate::str::contains("key1"))
        .stdout(predicate::str::contains("key2"));
}

#[test]
fn list_all_json_output() {
    let dir = tempdir().unwrap();
    let store = dir.path().join("test.db");

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
        .args(["set", "mykey", "myvalue"])
        .assert()
        .success();

    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .args(["list", "-a", "--json"])
        .assert()
        .success()
        .stdout(is_valid_json())
        .stdout(predicate::str::contains("mykey"))
        .stdout(predicate::str::contains("updated"))
        .stdout(predicate::str::contains("value").not());
}

#[test]
fn info_json_output() {
    let dir = tempdir().unwrap();
    let store = dir.path().join("test.db");

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
        .args(["info", "--json"])
        .assert()
        .success()
        .stdout(is_valid_json())
        .stdout(predicate::str::contains("XChaCha20-Poly1305"));
}

#[test]
fn get_key_clip_timeout_zero_fails() {
    let dir = tempdir().unwrap();
    let store = dir.path().join("test.db");

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
        .args(["set", "mykey", "myvalue"])
        .assert()
        .success();

    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .args(["get", "mykey", "--clip", "--timeout", "0"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("timeout must be greater than 0"));
}

#[test]
#[ignore]
fn get_key_clip() {
    let dir = tempdir().unwrap();
    let store = dir.path().join("test.db");

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
        .args(["set", "mykey", "myvalue"])
        .assert()
        .success();

    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .args(["get", "mykey", "--clip", "--timeout", "1"])
        .assert()
        .success()
        .stderr(predicate::str::contains("Secret copied to clipboard"))
        .stderr(predicate::str::contains("Clipboard"));
}
