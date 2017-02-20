# iron-csrf

CSRF protection for the Rust webframework Iron.

`iron-csrf` uses Ed25519 DSA or HMAC to sign and verify timestamped CSRF tokens.

There is an example `iron` server in the directory [./examples](./examples).

## Alpha Software

This code is not at this time suitable for any production deployment. It has not been
verified and the API is unstable. The current state is best described as "just barely
functional." Use with extreme caution.

## Contributing

Please make all pull requests to the `develop` branch.

### Bugs

This project has a **full disclosure** policy on security related errors. Please
treat these errors like all other bugs and file a public issue.

## Legal

### License

This work is licensed under the MIT license. See [LICENSE](./LICENSE) for details.

### Cryptography Notice

This software includes and uses cryptographic software. Your current country may have
restrictions on the import, export, possesion, or use cryptographic software. Check
your country's relevant laws before using this in any way. See
[Wassenaar](http://www.wassenaar.org/) for more info.
