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

pub fn run(runtime: &tokio::runtime::Runtime, name: &str, address: &str) -> Result<()> {
    let url = Url::parse(address).map_err(|error| Error::user(format!("bad address: {error}")))?;
    if url.password().is_some() {
        return Err(Error::user(
            "leave the password out of the address: rivet asks for it, so it stays out of \
             your shell history",
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
    let text = with_connection(&path, &current, name, address, &password_uri)?;

    let (mut request, driver) = parse(address)?;
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
    let text = format!(
        "{current}{separator}\n[connections.{name}]\nurl = {}\npassword = {}\n",
        string(address),
        string(password_uri)
    );
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
        )
        .unwrap();
        assert!(with_connection(path, &first, "a", "mysql://u@h/d", "keychain://rivet/a").is_err());
        assert!(
            with_connection(path, &first, "a.b", "mysql://u@h/d", "keychain://rivet/a.b").is_err()
        );
    }
}
