# jgpg

A Rust binary and library for converting `gpg --list-keys` (`apt-key list` etc.) output to JSON in DevOps, CI/CD pipelines. `jgpg` parses human-oriented GPG keyring listings into structured JSON, including key metadata, user IDs, trust indicators, and subkeys.

## Usage

Pipe GPG output into the tool:
