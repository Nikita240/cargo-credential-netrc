use cargo_credential::{
    Action, CacheControl, Credential, CredentialResponse, RegistryInfo, Secret,
};
use clap::Parser;
use netrc::Netrc;
use url::{Host, Url};

/// Cargo credential provider that parses your .netrc file to get credentials.
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// The format of the credential token given the netrc variables as an input.
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
        let _args =
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
                        Ok(CredentialResponse::Get {
                            token: format!("Bearer {}", authenticator.password).into(),
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
