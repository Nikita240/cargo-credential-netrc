//! Cargo credential provider that parses your .netrc file to get credentials.
//!
//! While this may not be the most secure or sophisticated way to manage your credentials,
//! you may already be using .netrc files to handle your authentication for other tools.
//! For such cases, this credential provider can be a useful drop in solution for
//! authenticating with private cargo registries.
//!
//! ## Usage
//!
//! Different private cargo registry providers expect different things in the token.
//! As a result, there is no way to generate the token from the .netrc file that will
//! work for all cases. To address this, this credential provider REQUIRES you to specify
//! the format of the token using the [handlebars templating language](https://handlebarsjs.com/)
//! with the `--format` argument.
//!
//! The following variables are available:
//! - `login`
//! - `account`
//! - `password`
//!
//! *NOTE: If your token format requires a space, you MUST use a [credential alias](https://doc.rust-lang.org/cargo/reference/config.html#credential-alias)
//! to specify the token format.*
//!
//! ## Example
//!
//! Here is an example of how to format a token for JFrog's Artifactory:
//!
//! ```toml
//! [credential-alias]
//! cargo-credential-artifactory = ["cargo-credential-netrc", "--format", "Bearer {{password}}"]
//!
//! [registries.artifactory]
//! index = "sparse+<YOUR_ARTIFACTORY_URL>"
//! credential-provider = "cargo-credential-artifactory"
//! ```

use std::collections::HashMap;

use cargo_credential::{
    Action, CacheControl, Credential, CredentialResponse, RegistryInfo, Secret,
};
use clap::Parser;
use handlebars::Handlebars;
use netrc::Netrc;
use url::{Host, Url};

/// Cargo credential provider that parses your .netrc file to get credentials.
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// The format of the credential token expressed using the handlebars templating language.
    ///
    /// The following variables are available:
    /// - login
    /// - account
    /// - password
    ///
    /// Examples:
    /// - `{{login}}:{{password}}`
    /// - `Bearer {{password}}`
    #[arg(required = true)]
    format: String,
}

struct NetrcCredential;

impl Credential for NetrcCredential {
    fn perform(
        &self,
        registry: &RegistryInfo<'_>,
        action: &Action<'_>,
        args: &[&str],
    ) -> Result<CredentialResponse, cargo_credential::Error> {
        let args =
            Args::try_parse_from(args).map_err(|e| cargo_credential::Error::Other(Box::new(e)))?;

        match action {
            Action::Get(_) => {
                // Parse the url to get the host.
                let host = match Url::parse(registry.index_url)
                    .map_err(|e| cargo_credential::Error::Other(Box::new(e)))?
                    .host()
                {
                    Some(Host::Domain(host)) => host.to_string(),
                    Some(Host::Ipv4(ip)) => ip.to_string(),
                    Some(Host::Ipv6(ip)) => ip.to_string(),
                    _ => return Err(cargo_credential::Error::UrlNotSupported),
                };

                // Parse the .netrc file.
                let netrc =
                    Netrc::new().map_err(|e| cargo_credential::Error::Other(Box::new(e)))?;

                match netrc.hosts.get(&host) {
                    Some(authenticator) => {
                        let handlebars = Handlebars::new();

                        let mut data = HashMap::new();
                        data.insert("login", Secret::from(authenticator.login.clone()));
                        data.insert("account", Secret::from(authenticator.account.clone()));
                        data.insert("password", Secret::from(authenticator.password.clone()));

                        let token: Secret<String> = handlebars
                            .render_template(&args.format, &data)
                            .map_err(|e| cargo_credential::Error::Other(Box::new(e)))?
                            .into();

                        Ok(CredentialResponse::Get {
                            token,
                            cache: CacheControl::Session,
                            operation_independent: true,
                        })
                    }
                    None => Err(cargo_credential::Error::NotFound),
                }
            }
            // If a credential provider doesn't support a given operation, it should respond with `OperationNotSupported`.
            _ => Err(cargo_credential::Error::OperationNotSupported),
        }
    }
}

fn main() {
    cargo_credential::main(NetrcCredential);
}
