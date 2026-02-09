use anyhow::{Result, bail};
use std::io::{self, Read};
use zeroize::Zeroizing;

pub fn read_password() -> Result<Zeroizing<String>> {
    //  Environment Variable
    //  KEYNEST_PASSWORD="supersecret" keynest get github_token
    if let Ok(pw) = std::env::var("KEYNEST_PASSWORD")
        && !pw.is_empty()
    {
        return Ok(Zeroizing::new(pw));
    }

    //  stdin (Pipeline)
    //  echo "supersecret" | keynest get github_token
    //  printf "%s" "$KEYNEST_PASSWORD" | keynest get github_token
    if !atty::is(atty::Stream::Stdin) {
        let mut buf = String::new();
        io::stdin().read_to_string(&mut buf)?;
        let pw = buf.trim_end().to_string();

        if !pw.is_empty() {
            return Ok(Zeroizing::new(pw));
        }
    }

    //  Interaktiv (TTY)
    if atty::is(atty::Stream::Stdin) {
        let pw = rpassword::prompt_password("Password: ")?;
        if !pw.is_empty() {
            return Ok(Zeroizing::new(pw));
        }
    }

    bail!("No password provided")
}
