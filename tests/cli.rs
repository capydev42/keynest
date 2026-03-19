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

    // --prompt and value together should fail
    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .args(["set", "mykey", "value", "--prompt"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "cannot use value argument together with --prompt",
        ));
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

#[test]
fn exec_print_all_keys() {
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
        .args(["exec", "--print", "--", "env"])
        .assert()
        .success()
        .stdout(predicate::str::contains("MYKEY"))
        .stdout(predicate::str::contains("myvalue"));
}

#[test]
fn exec_with_prefix() {
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
        .args(["set", "api_key", "secret123"])
        .assert()
        .success();

    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .args(["exec", "--prefix", "MY_", "--print", "--", "env"])
        .assert()
        .success()
        .stdout(predicate::str::contains("MY_API_KEY"))
        .stdout(predicate::str::contains("secret123"));
}

#[test]
fn exec_only_specific_keys() {
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
        .args(["set", "key1", "value1"])
        .assert()
        .success();

    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .args(["set", "key2", "value2"])
        .assert()
        .success();

    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .args(["exec", "--only", "key1", "--print", "--", "env"])
        .assert()
        .success()
        .stdout(predicate::str::contains("KEY1"))
        .stdout(predicate::str::contains("value1"))
        .stdout(predicate::str::contains("KEY2").not());
}

#[test]
fn export_json_to_stdout() {
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
        .args(["set", "api_key", "secret123"])
        .assert()
        .success();

    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .args(["export"])
        .assert()
        .success()
        .stdout(is_valid_json())
        .stdout(predicate::str::contains("api_key"))
        .stdout(predicate::str::contains("secret123"));
}

#[test]
fn export_env_format_to_file() {
    let dir = tempdir().unwrap();
    let store = dir.path().join("test.db");
    let export_file = dir.path().join("secrets.env");

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
        .args(["set", "DB_HOST", "localhost"])
        .assert()
        .success();

    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .args(["export", "--format", "env"])
        .arg(&export_file)
        .assert()
        .success();

    let content = std::fs::read_to_string(&export_file).unwrap();
    assert!(content.contains("DB_HOST=localhost"));
}

#[test]
fn export_json_format_to_file() {
    let dir = tempdir().unwrap();
    let store = dir.path().join("test.db");
    let export_file = dir.path().join("secrets.json");

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
        .args(["set", "api_key", "abc123"])
        .assert()
        .success();

    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .args(["export"])
        .arg(&export_file)
        .assert()
        .success();

    let content = std::fs::read_to_string(&export_file).unwrap();
    assert!(content.contains("\"api_key\""));
    assert!(content.contains("abc123"));
}

#[test]
fn export_format_auto_detected_from_extension() {
    let dir = tempdir().unwrap();
    let store = dir.path().join("test.db");
    let export_file = dir.path().join("exported.env");

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
        .args(["set", "KEY1", "val1"])
        .assert()
        .success();

    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .arg("export")
        .arg(&export_file)
        .assert()
        .success();

    let content = std::fs::read_to_string(&export_file).unwrap();
    assert!(content.contains("KEY1=val1"));
}

#[test]
fn export_with_prefix() {
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
        .args(["set", "API_KEY", "secret1"])
        .assert()
        .success();

    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .args(["set", "DB_PASS", "secret2"])
        .assert()
        .success();

    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .args(["export", "--prefix", "API_"])
        .assert()
        .success()
        .stdout(predicate::str::contains("API_KEY"))
        .stdout(predicate::str::contains("secret1"))
        .stdout(predicate::str::contains("DB_PASS").not());
}

#[test]
fn export_empty_store() {
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
        .arg("export")
        .assert()
        .success()
        .stdout(predicate::str::contains("No secrets to export"));
}

#[test]
fn import_env_file() {
    let dir = tempdir().unwrap();
    let store = dir.path().join("test.db");
    let import_file = dir.path().join("import.env");

    std::fs::write(&import_file, "API_KEY=secret123\nDB_PASS=postgres").unwrap();

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
        .arg("import")
        .arg(&import_file)
        .assert()
        .success()
        .stdout(predicate::str::contains("Imported 2 secret(s)"));

    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .args(["get", "API_KEY"])
        .assert()
        .success()
        .stdout(predicate::str::contains("secret123"));

    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .args(["get", "DB_PASS"])
        .assert()
        .success()
        .stdout(predicate::str::contains("postgres"));
}

#[test]
fn import_json_file() {
    let dir = tempdir().unwrap();
    let store = dir.path().join("test.db");
    let import_file = dir.path().join("import.json");

    std::fs::write(&import_file, r#"{"api_key": "abc123", "token": "xyz789"}"#).unwrap();

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
        .arg("import")
        .arg(&import_file)
        .assert()
        .success()
        .stdout(predicate::str::contains("Imported 2 secret(s)"));

    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .args(["get", "api_key"])
        .assert()
        .success()
        .stdout(predicate::str::contains("abc123"));
}

#[test]
fn import_explicit_format() {
    let dir = tempdir().unwrap();
    let store = dir.path().join("test.db");
    let import_file = dir.path().join("secrets.txt");

    std::fs::write(&import_file, "KEY=value\nKEY2=val2").unwrap();

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
        .args(["import", "--format", "env"])
        .arg(&import_file)
        .assert()
        .success()
        .stdout(predicate::str::contains("Imported 2 secret(s)"));
}

#[test]
fn import_skips_existing_keys_without_overwrite() {
    let dir = tempdir().unwrap();
    let store = dir.path().join("test.db");
    let import_file = dir.path().join("import.env");

    std::fs::write(&import_file, "EXISTING=newvalue\nNEWKEY=newvalue").unwrap();

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
        .args(["set", "EXISTING", "oldvalue"])
        .assert()
        .success();

    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .arg("import")
        .arg(&import_file)
        .assert()
        .success()
        .stdout(predicate::str::contains("Imported 1 secret(s)"))
        .stdout(predicate::str::contains("Skipped 1 existing"));

    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .args(["get", "EXISTING"])
        .assert()
        .success()
        .stdout(predicate::str::contains("oldvalue"));
}

#[test]
fn import_overwrites_existing_keys() {
    let dir = tempdir().unwrap();
    let store = dir.path().join("test.db");
    let import_file = dir.path().join("import.env");

    std::fs::write(&import_file, "MYKEY=updated").unwrap();

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
        .args(["set", "MYKEY", "original"])
        .assert()
        .success();

    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .args(["import", "--overwrite"])
        .arg(&import_file)
        .assert()
        .success()
        .stdout(predicate::str::contains("Imported 1 secret(s)"));

    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .args(["get", "MYKEY"])
        .assert()
        .success()
        .stdout(predicate::str::contains("updated"));
}

#[test]
fn import_unknown_format_fails() {
    let dir = tempdir().unwrap();
    let store = dir.path().join("test.db");
    let import_file = dir.path().join("secrets.yaml");

    std::fs::write(&import_file, "key: value").unwrap();

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
        .arg("import")
        .arg(&import_file)
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot detect format"));
}

#[test]
fn import_empty_file() {
    let dir = tempdir().unwrap();
    let store = dir.path().join("test.db");
    let import_file = dir.path().join("empty.env");

    std::fs::write(&import_file, "").unwrap();

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
        .arg("import")
        .arg(&import_file)
        .assert()
        .success()
        .stdout(predicate::str::contains("No secrets found"));
}

#[test]
fn import_env_with_comments() {
    let dir = tempdir().unwrap();
    let store = dir.path().join("test.db");
    let import_file = dir.path().join("with_comments.env");

    std::fs::write(
        &import_file,
        "# This is a comment\nKEY1=value1\n# Another comment\nKEY2=value2",
    )
    .unwrap();

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
        .arg("import")
        .arg(&import_file)
        .assert()
        .success()
        .stdout(predicate::str::contains("Imported 2 secret(s)"));
}

#[test]
fn import_env_with_quoted_values() {
    let dir = tempdir().unwrap();
    let store = dir.path().join("test.db");
    let import_file = dir.path().join("quoted.env");

    std::fs::write(&import_file, "API_KEY=\"abc 123\"\nPASSWORD='pa$$word'").unwrap();

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
        .arg("import")
        .arg(&import_file)
        .assert()
        .success()
        .stdout(predicate::str::contains("Imported 2 secret(s)"));

    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .args(["get", "API_KEY"])
        .assert()
        .success()
        .stdout(predicate::str::contains("abc 123"));

    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .args(["get", "PASSWORD"])
        .assert()
        .success()
        .stdout(predicate::str::contains("pa$$word"));
}

#[test]
fn export_env_escapes_special_characters() {
    let dir = tempdir().unwrap();
    let store = dir.path().join("test.db");
    let export_file = dir.path().join("escaped.env");

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
        .args(["set", "KEY", "value with spaces"])
        .assert()
        .success();

    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .args(["export", "--format", "env"])
        .arg(&export_file)
        .assert()
        .success();

    let content = std::fs::read_to_string(&export_file).unwrap();
    assert!(content.contains("\"value with spaces\""));
}

#[test]
fn export_import_roundtrip() {
    let dir = tempdir().unwrap();
    let store1 = dir.path().join("test1.db");
    let store2 = dir.path().join("test2.db");
    let export_file = dir.path().join("roundtrip.env");

    // Create first keystore with secrets
    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store1)
        .arg("init")
        .assert()
        .success();

    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store1)
        .args(["set", "API_KEY", "secret123"])
        .assert()
        .success();

    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store1)
        .args(["set", "DB_PASS", "postgres"])
        .assert()
        .success();

    // Export from first keystore
    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store1)
        .args(["export", "--format", "env"])
        .arg(&export_file)
        .assert()
        .success();

    // Create second keystore
    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store2)
        .arg("init")
        .assert()
        .success();

    // Import into second keystore
    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store2)
        .arg("import")
        .arg(&export_file)
        .assert()
        .success()
        .stdout(predicate::str::contains("Imported 2 secret(s)"));

    // Verify secrets in second keystore
    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store2)
        .args(["get", "API_KEY"])
        .assert()
        .success()
        .stdout(predicate::str::contains("secret123"));

    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store2)
        .args(["get", "DB_PASS"])
        .assert()
        .success()
        .stdout(predicate::str::contains("postgres"));
}

#[test]
fn import_with_prefix() {
    let dir = tempdir().unwrap();
    let store = dir.path().join("test.db");
    let import_file = dir.path().join("prefix.env");

    std::fs::write(
        &import_file,
        "API_KEY=secret1\nDB_PASS=secret2\nOTHER_KEY=secret3",
    )
    .unwrap();

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
        .args(["import", "--prefix", "API_"])
        .arg(&import_file)
        .assert()
        .success()
        .stdout(predicate::str::contains("Imported 1 secret(s)"))
        .stdout(predicate::str::contains("Filtered 2 secret(s)"));

    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .args(["get", "API_KEY"])
        .assert()
        .success()
        .stdout(predicate::str::contains("secret1"));

    bin()
        .env("KEYNEST_PASSWORD", "pw")
        .arg("--store")
        .arg(&store)
        .args(["get", "DB_PASS"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}
