
# `cargo-credential-netrc` <!-- omit from toc -->

<!-- cargo-rdme start -->

Cargo credential provider that parses your .netrc file to get credentials.

While this may not be the most secure or sophisticated way to manage your credentials,
you may already be using .netrc files to handle your authentication for other tools.
For such cases, this credential provider can be a useful drop in solution for
authenticating with private cargo registries.

### Usage

Different private cargo registry providers expect different things in the token.
As a result, there is no way to generate the token from the .netrc file that will
work for all cases. To address this, this credential provider REQUIRES you to specify
the format of the token using the [handlebars templating language](https://handlebarsjs.com/)
with the `--format` argument.

The following variables are available:
- `login`
- `account`
- `password`

*NOTE: If your token format requires a space, you MUST use a [credential alias](https://doc.rust-lang.org/cargo/reference/config.html#credential-alias)
to specify the token format.*

### Example

Here is an example of how to format a token for JFrog's Artifactory:

```toml
[credential-alias]
cargo-credential-artifactory = ["cargo-credential-netrc", "--format", "Bearer {{password}}"]

[registries.artifactory]
index = "sparse+<YOUR_ARTIFACTORY_URL>"
credential-provider = "cargo-credential-artifactory"
```

<!-- cargo-rdme end -->
