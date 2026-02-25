use anyhow::{Result, bail};
use std::io::{self, BufRead, IsTerminal};
use zeroize::Zeroizing;

pub fn read_password() -> Result<Zeroizing<String>> {
    //  Environment Variable
    //  KEYNEST_PASSWORD="supersecret" keynest get github_token
    if let Ok(pw) = std::env::var("KEYNEST_PASSWORD") {
        if !pw.is_empty() {
            return Ok(Zeroizing::new(pw));
        }
    }

    //  stdin (Pipeline)
    //  echo "supersecret" | keynest get github_token
    //  printf "%s" "$KEYNEST_PASSWORD" | keynest get github_token
    if !io::stdin().is_terminal() {
        let mut buf = String::new();
        io::stdin().read_line(&mut buf)?;
        let pw = buf.trim_end().to_string();

        if !pw.is_empty() {
            return Ok(Zeroizing::new(pw));
        }
    }

    //  Interaktiv (TTY)
    if io::stdin().is_terminal() {
        let pw = rpassword::prompt_password("Password: ")?;
        if !pw.is_empty() {
            return Ok(Zeroizing::new(pw));
        }
    }

    bail!("No password provided")
}

pub fn read_new_password_with_confirmation() -> Result<Zeroizing<String>> {
    if !io::stdin().is_terminal() {
        let stdin = io::stdin();
        let mut handle = stdin.lock();

        let mut pw1 = Zeroizing::new(String::new());
        let mut pw2 = Zeroizing::new(String::new());

        handle.read_line(&mut pw1)?;
        handle.read_line(&mut pw2)?;

        trim_newline(&mut pw1);
        trim_newline(&mut pw2);

        if pw1.is_empty() {
            bail!("password cannot be empty");
        }

        if pw1 != pw2 {
            bail!("passwords do not match");
        }

        return Ok(pw1);
    }

    let pw1 = rpassword::prompt_password("New password: ")?;
    let pw2 = rpassword::prompt_password("Confirm password: ")?;

    if pw1.is_empty() {
        bail!("password cannot be empty");
    }

    if pw1 != pw2 {
        bail!("passwords do not match");
    }

    Ok(Zeroizing::new(pw1))
}

fn trim_newline(s: &mut String) {
    while s.ends_with('\n') || s.ends_with('\r') {
        s.pop();
    }
}
