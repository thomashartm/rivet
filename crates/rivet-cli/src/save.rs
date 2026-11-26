//! `rivet save <name> <url>`: asks for the password, checks that the
//! connection works, stores the password in the keychain and adds
//! `[connections.<name>]` to the user settings file. With `?tls_cert=` in
//! the address and `--key-file`, it stores the key of the client
//! certificate instead and asks for no password.

use std::path::Path;

use rivet_core::secrets::{KEYCHAIN_SCHEME, KeychainBackend};
use rivet_core::settings::{Layer, Settings, user_settings_path};
use rivet_sdk::error::{Error, Result};
use rivet_sdk::extension::Credential;
use rivet_sdk::secret::Secret;
use url::Url;

use crate::{parse, read_certificate, saved};

/// The keychain service of the secrets that `rivet save` stores.
const SERVICE: &str = "rivet";

/// The flags of `rivet save`. A profile flag that is not set is not written.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Flags {
    read_only: bool,
    confirm_on_write: bool,
    environment: Option<String>,
    /// The PEM key file of the client certificate. Only its path.
    key_file: Option<String>,
}

/// `<name> <address>` and the flags, in any order. Refuses an unknown or
/// repeated flag and `--env` or `--key-file` without a value.
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
            "--key-file" if flags.key_file.is_some() => return Err(repeated()),
            "--key-file" => match rest.next() {
                Some(file) if !file.is_empty() && !file.starts_with('-') => {
                    flags.key_file = Some(file.clone());
                }
                _ => {
                    return Err(Error::user(
                        "--key-file needs the path of the PEM key file, for example \
                         `--key-file client.key`",
                    ));
                }
            },
            _ if arg.starts_with('-') => {
                return Err(Error::user(format!(
                    "unknown flag `{arg}`: use --read-only, --confirm-on-write, --env <label> \
                     or --key-file <path>"
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

/// `address` with `tls_key=<key_uri>` added if it has `tls_cert`, else
/// `address` unchanged. A client certificate needs `key_file`, and
/// `key_file` needs a client certificate; `tls_key` in `address` is
/// refused, because rivet stores the key.
fn with_key_uri(address: &str, key_uri: &str, key_file: Option<&str>) -> Result<String> {
    let mut url =
        Url::parse(address).map_err(|error| Error::user(format!("bad address: {error}")))?;
    let has = |name: &str| url.query_pairs().any(|(key, _)| key == name);
    if has("tls_key") {
        return Err(Error::user(
            "leave `tls_key` out of the address: give the key file with --key-file <path>, \
             and rivet stores the key in the keychain",
        ));
    }
    match (has("tls_cert"), key_file) {
        (true, Some(_)) => {
            url.query_pairs_mut().append_pair("tls_key", key_uri);
            Ok(url.into())
        }
        (true, None) => Err(Error::user(
            "a client certificate (`tls_cert`) needs its key: add --key-file <PEM key file>",
        )),
        (false, Some(_)) => Err(Error::user(
            "--key-file needs a client certificate: add `tls_cert=<PEM file>` to the address",
        )),
        (false, None) => Ok(address.to_owned()),
    }
}

/// The text of the certificate file and the key from the key file. The key
/// text goes into a `Secret` at once, so no error or log shows it.
fn read_client_certificate(certificate: &Path, key_file: &str) -> Result<(String, Secret)> {
    let certificate = read_certificate(certificate)?;
    let key = std::fs::read_to_string(key_file)
        .map(Secret::from)
        .map_err(|error| {
            Error::user(format!("cannot read the key file {key_file}")).with_source(error)
        })?;
    Ok((certificate, key))
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
    let key_path = format!("{SERVICE}/{name}-key");
    let key_uri = format!("{KEYCHAIN_SCHEME}://{key_path}");
    let address = &with_key_uri(address, &key_uri, flags.key_file.as_deref())?;
    // Validates the address (TLS parameters included) before the prompt.
    let (mut request, driver) = parse(address)?;
    // The drivers take the client certificate only as a credential.
    let certificate = request
        .profile
        .tls
        .client_certificate
        .take()
        .zip(flags.key_file.as_deref())
        .map(|(certificate, key_file)| read_client_certificate(&certificate.certificate, key_file))
        .transpose()?;
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
    let password_path = format!("{SERVICE}/{name}");
    let password_uri = format!("{KEYCHAIN_SCHEME}://{password_path}");
    let password_line = certificate.is_none().then_some(password_uri.as_str());
    let text = with_connection(&path, &current, name, address, password_line, &flags)?;

    let (secret_path, secret, stored) = match certificate {
        Some((certificate, key)) => {
            request.credentials.credential = Credential::ClientCertificate {
                certificate,
                private_key: Secret::from(key.expose().to_owned()),
            };
            (key_path, key, format!("the key in {key_uri}"))
        }
        None => {
            let user = request.credentials.user.clone().unwrap_or_default();
            let typed = rpassword::prompt_password(format!(
                "password for {user}@{}: ",
                url.host_str().unwrap_or("")
            ))
            .map_err(|error| Error::user("cannot read the password").with_source(error))?;
            let password = Secret::from(typed);
            request.credentials.credential =
                Credential::Password(Secret::from(password.expose().to_owned()));
            (
                password_path,
                password,
                format!("the password in {password_uri}"),
            )
        }
    };
    // Only a secret that works is stored.
    drop(runtime.block_on(driver.connect(request))?);
    runtime.block_on(KeychainBackend.store(&secret_path, secret))?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|error| {
            Error::user(format!("cannot create {}", dir.display())).with_source(error)
        })?;
    }
    std::fs::write(&path, text).map_err(|error| {
        Error::user(format!("cannot write {}", path.display())).with_source(error)
    })?;
    eprintln!(
        "saved `{name}` in {} with {stored}. Open it with: rivet {name}",
        path.display()
    );
    Ok(())
}

/// The settings text `current` plus the table of the new connection, with
/// a `password` line if `password_uri` is set. The result passes the
/// settings check (no password in `url`, for example).
fn with_connection(
    path: &Path,
    current: &str,
    name: &str,
    address: &str,
    password_uri: Option<&str>,
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
        "{current}{separator}\n[connections.{name}]\nurl = {}\n",
        string(address)
    );
    if let Some(uri) = password_uri {
        text.push_str(&format!("password = {}\n", string(uri)));
    }
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
    use rivet_sdk::error::ErrorCategory;

    use super::*;

    #[test]
    fn with_connection_appends_a_table_that_reads_back() {
        let path = Path::new("settings.toml");
        let text = with_connection(
            path,
            "schema_version = 1",
            "prod",
            "postgres://app@db/x",
            Some("keychain://rivet/prod"),
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
            Some("keychain://rivet/a"),
            &Flags::default(),
        )
        .unwrap();
        let again = |name, uri| {
            with_connection(path, &first, name, "mysql://u@h/d", uri, &Flags::default())
        };
        assert!(again("a", Some("keychain://rivet/a")).is_err());
        assert!(again("a.b", None).is_err());
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
            ..Flags::default()
        };
        let text = with_connection(
            Path::new("s.toml"),
            "schema_version = 1\n",
            "prod",
            "postgres://app@db/x",
            Some("keychain://rivet/prod"),
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
            Some("keychain://rivet/x"),
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
            "--key-file",
            "c.key",
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
                key_file: Some("c.key".to_owned()),
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
            &["n", "u", "--key-file", "a.key", "--key-file", "b.key"],
            &["n", "u", "--key-file"],
            &["n", "u", "--key-file", "--read-only"],
            &["n", "u", "--key-file", ""],
            &["n"],
            &["n", "u", "extra"],
        ] {
            assert!(parse_args(&args(bad)).is_err(), "{bad:?}");
        }
    }

    /// A directory of its own for the files of one test.
    fn scratch(test: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("rivet-save-{test}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    const KEY: &str =
        "-----BEGIN PRIVATE KEY-----\nkey-text-that-must-not-leak\n-----END PRIVATE KEY-----\n";

    #[test]
    fn with_key_uri_adds_the_key_uri_that_parse_reads() {
        let url = "postgres://app@db/x?tls_cert=%2Fc%20x.pem";
        let address = with_key_uri(url, "keychain://rivet/prod-key", Some("c.key")).unwrap();
        let certificate = parse(&address)
            .unwrap()
            .0
            .profile
            .tls
            .client_certificate
            .unwrap();
        assert_eq!(certificate.certificate, Path::new("/c x.pem"));
        assert_eq!(
            certificate.private_key.as_str(),
            "keychain://rivet/prod-key"
        );
        assert_eq!(
            with_key_uri(
                "postgres://app@db/x?tls_cert=/p/c.pem",
                "keychain://rivet/prod-key",
                Some("c.key")
            )
            .unwrap(),
            "postgres://app@db/x?tls_cert=/p/c.pem&tls_key=keychain%3A%2F%2Frivet%2Fprod-key"
        );
        // Without a client certificate the address stays as typed.
        assert_eq!(
            with_key_uri("MYSQL://u@H/d?tls=off", "keychain://rivet/x-key", None).unwrap(),
            "MYSQL://u@H/d?tls=off"
        );
    }

    #[test]
    fn with_key_uri_refuses_a_missing_or_given_key() {
        let key = "keychain://rivet/p-key";
        for (address, key_file, says) in [
            (
                "postgres://a@h/d",
                Some("c.key"),
                "needs a client certificate",
            ),
            ("postgres://a@h/d?tls_cert=c.pem", None, "add --key-file"),
            (
                "postgres://a@h/d?tls_cert=c.pem&tls_key=keychain://rivet/k",
                Some("c.key"),
                "leave `tls_key` out",
            ),
            (
                "postgres://a@h/d?tls_cert=c.pem&tls_key=keychain://rivet/k",
                None,
                "leave `tls_key` out",
            ),
        ] {
            let error = with_key_uri(address, key, key_file).err().unwrap();
            assert_eq!(error.category(), ErrorCategory::User, "{address}");
            assert!(error.message().contains(says), "{address}: {error}");
        }
    }

    /// Each refusal comes before the settings file, the prompt and the
    /// connect. The host does not listen, so nothing is stored even if a
    /// check is missing.
    #[test]
    fn run_refuses_a_bad_certificate_save_before_any_prompt_or_connect() {
        let dir = scratch("refuse");
        let (cert, key) = (dir.join("c.pem"), dir.join("c.key"));
        std::fs::write(&cert, "certificate").unwrap();
        std::fs::write(&key, KEY).unwrap();
        let missing = dir.join("missing");
        let at = |query: &str| format!("postgres://app@127.0.0.1:1/d?{query}");
        let cert_query = format!("tls_cert={}", cert.display());
        let runtime = tokio::runtime::Runtime::new().unwrap();
        for (address, key_file, says) in [
            (
                at("tls=on"),
                Some(&key),
                "needs a client certificate".to_owned(),
            ),
            (at(&cert_query), None, "add --key-file".to_owned()),
            (
                at(&format!("{cert_query}&tls_key=keychain://rivet/k")),
                Some(&key),
                "leave `tls_key` out".to_owned(),
            ),
            (
                format!("postgres://app:pw@127.0.0.1:1/d?{cert_query}"),
                Some(&key),
                "leave the password out".to_owned(),
            ),
            (
                at(&format!("tls=off&{cert_query}")),
                Some(&key),
                "needs TLS".to_owned(),
            ),
            (
                at(&format!("tls_cert={}", missing.display())),
                Some(&key),
                missing.display().to_string(),
            ),
            (
                at(&cert_query),
                Some(&missing),
                format!("cannot read the key file {}", missing.display()),
            ),
        ] {
            let mut list = vec!["n".to_owned(), address.clone()];
            if let Some(file) = key_file {
                list.extend(["--key-file".to_owned(), file.display().to_string()]);
            }
            let error = run(&runtime, &list).err().unwrap();
            assert_eq!(error.category(), ErrorCategory::User, "{address}: {error}");
            assert!(error.message().contains(&says), "{address}: {error}");
            assert!(!format!("{error:?}").contains("must-not-leak"), "{error:?}");
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn with_connection_writes_the_key_uri_and_no_password() {
        let address =
            "postgres://app@db/x?tls_cert=c.pem&tls_key=keychain%3A%2F%2Frivet%2Fprod-key";
        let text = with_connection(
            Path::new("s.toml"),
            "schema_version = 1\n",
            "prod",
            address,
            None,
            &Flags::default(),
        )
        .unwrap();
        assert_eq!(
            text,
            format!("schema_version = 1\n\n[connections.prod]\nurl = \"{address}\"\n")
        );
        let mut settings = Settings::new();
        settings.set_layer(Layer::User, "t", &text).unwrap();
        let prod = saved(&settings, "prod").unwrap().unwrap();
        assert_eq!(prod.password, None);
        let certificate = parse(&prod.url)
            .unwrap()
            .0
            .profile
            .tls
            .client_certificate
            .unwrap();
        assert_eq!(
            certificate.private_key.as_str(),
            "keychain://rivet/prod-key"
        );
    }

    /// The key from the file reaches the driver, and the driver error for a
    /// bad certificate does not show it.
    #[tokio::test]
    async fn a_refused_key_never_shows_in_an_error() {
        let dir = scratch("leak");
        let (cert, key) = (dir.join("c.pem"), dir.join("c.key"));
        std::fs::write(
            &cert,
            "-----BEGIN CERTIFICATE-----\nMAA=\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        std::fs::write(&key, "not a key, but key-text-that-must-not-leak\n").unwrap();
        let address = format!("postgres://app@127.0.0.1:1/d?tls_cert={}", cert.display());
        let address = with_key_uri(&address, "keychain://rivet/n-key", Some("k")).unwrap();
        let (mut request, driver) = parse(&address).unwrap();
        let certificate = request.profile.tls.client_certificate.take().unwrap();
        let (certificate, private_key) =
            read_client_certificate(&certificate.certificate, &key.display().to_string()).unwrap();
        std::fs::remove_dir_all(dir).unwrap();
        assert!(private_key.expose().contains("must-not-leak"));
        request.credentials.credential = Credential::ClientCertificate {
            certificate,
            private_key,
        };
        assert!(!format!("{:?}", request.credentials).contains("must-not-leak"));
        let error = driver.connect(request).await.err().unwrap();
        assert_eq!(error.category(), ErrorCategory::User, "{error:?}");
        assert!(error.message().contains("private key"), "{error:?}");
        assert!(!format!("{error:?}").contains("must-not-leak"), "{error:?}");
    }
}
