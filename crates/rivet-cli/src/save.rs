//! `rivet save <name> <url>`: asks for the password, checks that the
//! connection works, stores the password in the keychain and adds
//! `[connections.<name>]` to the user settings file.

use std::path::Path;

use rivet_core::secrets::{KEYCHAIN_SCHEME, KeychainBackend};
use rivet_core::settings::{Layer, Settings, user_settings_path};
use rivet_sdk::error::{Error, Result};
use rivet_sdk::extension::Credential;
use rivet_sdk::secret::Secret;
use url::Url;

use crate::{parse, saved};

/// The keychain service of the passwords that `rivet save` stores.
const SERVICE: &str = "rivet";

/// The profile flags of `rivet save`. A flag that is not set is not written.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Flags {
    read_only: bool,
    confirm_on_write: bool,
    environment: Option<String>,
}

/// `<name> <address>` and the flags, in any order. Refuses an unknown or
/// repeated flag and `--env` without a value.
fn parse_args(args: &[String]) -> Result<(&str, &str, Flags)> {
    let mut flags = Flags::default();
    let mut positional = Vec::new();
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        let repeated = || Error::user(format!("`{arg}` is given twice"));
        match arg.as_str() {
            "--read-only" if flags.read_only => return Err(repeated()),
            "--read-only" => flags.read_only = true,
            "--confirm-on-write" if flags.confirm_on_write => return Err(repeated()),
            "--confirm-on-write" => flags.confirm_on_write = true,
            "--env" if flags.environment.is_some() => return Err(repeated()),
            "--env" => match rest.next() {
                Some(label) if !label.is_empty() && !label.starts_with('-') => {
                    flags.environment = Some(label.clone());
                }
                _ => return Err(Error::user("--env needs a label, for example `--env prod`")),
            },
            _ if arg.starts_with('-') => {
                return Err(Error::user(format!(
                    "unknown flag `{arg}`: use --read-only, --confirm-on-write or --env <label>"
                )));
            }
            _ => positional.push(arg.as_str()),
        }
    }
    match positional.as_slice() {
        [name, address] => Ok((name, address, flags)),
        _ => Err(Error::user("save needs <name> and <address>")),
    }
}

pub fn run(runtime: &tokio::runtime::Runtime, args: &[String]) -> Result<()> {
    let (name, address, flags) = parse_args(args)?;
    let url = Url::parse(address).map_err(|error| Error::user(format!("bad address: {error}")))?;
    if url.password().is_some() {
        return Err(Error::user(
            "leave the password out of the address: rivet asks for it, so it stays out of \
             your shell history",
        ));
    }
    // Validates the address (TLS parameters included) before the prompt.
    let (mut request, driver) = parse(address)?;
    // shortcut: no password to ask for and store with a client certificate;
    // save it without `password` once `rivet save` needs it.
    if request.profile.tls.client_certificate.is_some() {
        return Err(Error::user(
            "rivet save cannot save a client certificate yet: write the \
             [connections.<name>] table by hand, with `tls_cert` and `tls_key` in `url` and \
             no `password`",
        ));
    }
    let path = user_settings_path()?;
    let current = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            "schema_version = 1\n".to_owned()
        }
        Err(error) => {
            return Err(
                Error::user(format!("{}: cannot read the settings file", path.display()))
                    .with_source(error),
            );
        }
    };
    let password_uri = format!("{KEYCHAIN_SCHEME}://{SERVICE}/{name}");
    let text = with_connection(&path, &current, name, address, &password_uri, &flags)?;

    let user = request.credentials.user.clone().unwrap_or_default();
    let typed = rpassword::prompt_password(format!(
        "password for {user}@{}: ",
        url.host_str().unwrap_or("")
    ))
    .map_err(|error| Error::user("cannot read the password").with_source(error))?;
    let password = Secret::from(typed);
    request.credentials.credential =
        Credential::Password(Secret::from(password.expose().to_owned()));
    // Only a password that works is stored.
    drop(runtime.block_on(driver.connect(request))?);
    runtime.block_on(KeychainBackend.store(&format!("{SERVICE}/{name}"), password))?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|error| {
            Error::user(format!("cannot create {}", dir.display())).with_source(error)
        })?;
    }
    std::fs::write(&path, text).map_err(|error| {
        Error::user(format!("cannot write {}", path.display())).with_source(error)
    })?;
    eprintln!(
        "saved `{name}` in {} with the password in {password_uri}. Open it with: rivet {name}",
        path.display()
    );
    Ok(())
}

/// The settings text `current` plus the table of the new connection. The
/// result passes the settings check (no password in `url`, for example).
fn with_connection(
    path: &Path,
    current: &str,
    name: &str,
    address: &str,
    password_uri: &str,
    flags: &Flags,
) -> Result<String> {
    let mut settings = Settings::new();
    let source = path.display().to_string();
    settings.set_layer(Layer::User, &source, current)?;
    // Also checks the name.
    if saved(&settings, name)?.is_some() {
        return Err(Error::user(format!(
            "the connection `{name}` is already in {source}; change or remove it there"
        )));
    }
    let string = |value: &str| toml::Value::String(value.to_owned()).to_string();
    let separator = if current.ends_with('\n') || current.is_empty() {
        ""
    } else {
        "\n"
    };
    let mut text = format!(
        "{current}{separator}\n[connections.{name}]\nurl = {}\npassword = {}\n",
        string(address),
        string(password_uri)
    );
    if flags.read_only {
        text.push_str("read_only = true\n");
    }
    if flags.confirm_on_write {
        text.push_str("confirm_on_write = true\n");
    }
    if let Some(label) = &flags.environment {
        text.push_str(&format!("environment = {}\n", string(label)));
    }
    settings.set_layer(Layer::User, &source, &text)?;
    if saved(&settings, name)?.is_none() {
        return Err(Error::internal(format!(
            "the new table connections.{name} cannot be read back"
        )));
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_connection_appends_a_table_that_reads_back() {
        let path = Path::new("settings.toml");
        let text = with_connection(
            path,
            "schema_version = 1",
            "prod",
            "postgres://app@db/x",
            "keychain://rivet/prod",
            &Flags::default(),
        )
        .unwrap();
        assert_eq!(
            text,
            "schema_version = 1\n\n[connections.prod]\nurl = \"postgres://app@db/x\"\n\
             password = \"keychain://rivet/prod\"\n"
        );
        let mut settings = Settings::new();
        settings.set_layer(Layer::User, "t", &text).unwrap();
        assert_eq!(
            saved(&settings, "prod").unwrap().unwrap().url,
            "postgres://app@db/x"
        );
    }

    #[test]
    fn with_connection_refuses_a_duplicate_and_a_bad_name() {
        let path = Path::new("settings.toml");
        let first = with_connection(
            path,
            "schema_version = 1\n",
            "a",
            "mysql://u@h/d",
            "keychain://rivet/a",
            &Flags::default(),
        )
        .unwrap();
        let again = |name, uri| {
            with_connection(path, &first, name, "mysql://u@h/d", uri, &Flags::default())
        };
        assert!(again("a", "keychain://rivet/a").is_err());
        assert!(again("a.b", "keychain://rivet/a.b").is_err());
    }

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|arg| (*arg).to_owned()).collect()
    }

    #[test]
    fn with_connection_writes_the_flags_and_they_read_back() {
        let flags = Flags {
            read_only: true,
            confirm_on_write: true,
            environment: Some("prod".to_owned()),
        };
        let text = with_connection(
            Path::new("s.toml"),
            "schema_version = 1\n",
            "prod",
            "postgres://app@db/x",
            "keychain://rivet/prod",
            &flags,
        )
        .unwrap();
        let mut settings = Settings::new();
        settings.set_layer(Layer::User, "t", &text).unwrap();
        let prod = saved(&settings, "prod").unwrap().unwrap();
        assert!(prod.read_only && prod.confirm_on_write);
        assert_eq!(prod.environment.as_deref(), Some("prod"));
    }

    #[test]
    fn with_connection_escapes_the_label() {
        let flags = Flags {
            environment: Some("say \"hi\" \\ now".to_owned()),
            ..Flags::default()
        };
        let text = with_connection(
            Path::new("s.toml"),
            "schema_version = 1\n",
            "x",
            "mysql://u@h/d",
            "keychain://rivet/x",
            &flags,
        )
        .unwrap();
        let mut settings = Settings::new();
        settings.set_layer(Layer::User, "t", &text).unwrap();
        let x = saved(&settings, "x").unwrap().unwrap();
        assert_eq!(x.environment.as_deref(), Some("say \"hi\" \\ now"));
        assert!(!x.read_only && !x.confirm_on_write);
        assert!(!text.contains("read_only"));
    }

    #[test]
    fn parse_args_takes_the_flags_in_any_order() {
        let list = args(&[
            "--env",
            "prod",
            "n",
            "--read-only",
            "u",
            "--confirm-on-write",
        ]);
        let (name, address, flags) = parse_args(&list).unwrap();
        assert_eq!((name, address), ("n", "u"));
        assert_eq!(
            flags,
            Flags {
                read_only: true,
                confirm_on_write: true,
                environment: Some("prod".to_owned()),
            }
        );
    }

    #[test]
    fn parse_args_refuses_bad_input() {
        for bad in [
            &["n", "u", "--nope"][..],
            &["n", "u", "--read-only", "--read-only"],
            &["n", "u", "--confirm-on-write", "--confirm-on-write"],
            &["n", "u", "--env", "a", "--env", "b"],
            &["n", "u", "--env"],
            &["n", "u", "--env", "--read-only"],
            &["n", "u", "--env", ""],
            &["n"],
            &["n", "u", "extra"],
        ] {
            assert!(parse_args(&args(bad)).is_err(), "{bad:?}");
        }
    }
}
