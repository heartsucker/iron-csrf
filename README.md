# iron-csrf

CSRF protection for the Rust web framework Iron.

`iron-csrf` uses either ChaCha20Poly1305 or AES-GCM to sign and verify timestamped
CSRF cookies and their accompanying tokens.

There is an example `iron` server in the directory [./examples](./examples), and more
information can be found in the docs hosted at [docs.rs](https://docs.rs/iron-csrf/).
A complete reference implementation can be found on
[github](https://github.com/heartsucker/iron-reference).

## Contributing

Please make all pull requests to the `develop` branch.

### Bugs

This project has a **full disclosure** policy on security related errors. Please
treat these errors like all other bugs and file a public issue. Errors communicated
via other channels will be immediately made public.

## Legal

### License

This work is licensed under the MIT license. See [LICENSE](./LICENSE) for details.

### Cryptography Notice

This software includes and uses cryptographic software. Your current country may have
restrictions on the import, export, possession, or use of cryptographic software. Check
your country's relevant laws before using this in any way. See
[Wassenaar](http://www.wassenaar.org/) for more info.
