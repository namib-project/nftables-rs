<h1>
<p align="center">
  <a href="README.md">
    <img src="https://avatars.githubusercontent.com/u/74997251?s=400&u=72b0315c726d0b2e0a85d7da71cfc18ce8fb0d14&v=4" alt="Logo" width="160" height="160">
  </a>
  <br>nftables-rs
</h1>

<h3 align='center'> Automate modern Linux firewalls with nftables through its declarative and imperative JSON API in Rust. </h3>

<!-- primary badges -------------------------------------->
<p align="center">
  <!-- version -->
  <a href="https://crates.io/crates/nftables"><img src='https://img.shields.io/crates/v/nftables.svg' /></a>
  <!-- downloads -->
  <a href="https://crates.io/crates/nftables"><img alt="Crates.io Total Downloads" src="https://img.shields.io/crates/d/nftables"></a>
  <!-- docs.io -->
  <a href="https://docs.rs/nftables/latest/nftables/"><img alt="rs" src="https://img.shields.io/badge/docs.rs-nftables-green.svg"></a>
  <!-- actions: rust -->
  <a href="https://github.com/namib-project/nftables-rs/actions/workflows/rust.yml"><img alt="Actions Workflow Status" src="https://github.com/namib-project/nftables-rs/actions/workflows/rust.yml/badge.svg"></a>
  <!-- license -->
  <a href="LICENSE-MIT"><img alt="License" src="https://img.shields.io/crates/l/nftables.svg"></a>
</p>
<br/>

## Features 🌟

- 🛡️ **Safe and Easy-to-Use Abstraction**: Provides a high-level, safe abstraction over the [nftables JSON API](https://manpages.debian.org/testing/libnftables1/libnftables-json.5.en.html), making it easier and safer to work with nftables in Rust.

- 🛠️ **Comprehensive Functions**: Includes a wide range of functions to create, read, and apply nftables rulesets directly from Rust, streamlining the management of firewall rules.

- 📄 **JSON Parsing and Generation**: Offers detailed parsing and generation capabilities for nftables rulesets in JSON format, enabling seamless integration and manipulation of rulesets.

- 💡 **Inspired by nftnl-rs**: While taking inspiration from [nftnl-rs](https://github.com/mullvad/nftnl-rs), `nftables-rs` focuses on utilizing the JSON API for broader accessibility and catering to diverse use cases.

## Motivation

`nftables-rs` is a Rust library designed to provide a safe and easy-to-use abstraction over the nftables JSON API, known as libnftables-json. 

This library is engineered for developers who need to interact with nftables, the Linux kernel's next-generation firewalling tool, directly from Rust applications.
By abstracting the underlying JSON API, nftables-rs facilitates the creation, manipulation, and application of firewall rulesets without requiring deep knowledge of nftables' internal workings.

## Installation

```toml
[dependencies]
nftables = "0.3.0"
```

Linux nftables v0.9.3 or newer is required at runtime: `nft --version`

## Example

Here are some examples that show use cases of this library.
Check out the `tests/` directory for more usage examples.

### Apply ruleset to nftables

This example applies a ruleset that creates and deletes a table to nftables.

```rust
use nft::{batch::Batch, helper, schema, types};

/// Applies a ruleset to nftables.
fn test_apply_ruleset() {
    let ruleset = example_ruleset();
    nft::helper::apply_ruleset(&ruleset, None, None).unwrap();
}

fn example_ruleset() -> schema::Nftables {
    let mut batch = Batch::new();
    batch.add(schema::NfListObject::Table(schema::Table::new(
        types::NfFamily::IP,
        "test-table-01".to_string(),
    )));
    batch.delete(schema::NfListObject::Table(schema::Table::new(
        types::NfFamily::IP,
        "test-table-01".to_string(),
    )));
    batch.to_nftables()
}
```

### Parse/Generate nftables ruleset in JSON format

This example compares nftables' native JSON out to the JSON payload generated by this library.

```rust
fn test_chain_table_rule_inet() {
    // nft add table inet some_inet_table
    // nft add chain inet some_inet_table some_inet_chain '{ type filter hook forward priority 0; policy accept; }'
    let expected: Nftables = Nftables {
        objects: vec![
            NfObject::CmdObject(NfCmd::Add(NfListObject::Table(Table {
                family: NfFamily::INet,
                name: "some_inet_table".to_string(),
                handle: None,
            }))),
            NfObject::CmdObject(NfCmd::Add(NfListObject::Chain(Chain {
                family: NfFamily::INet,
                table: "some_inet_table".to_string(),
                name: "some_inet_chain".to_string(),
                newname: None,
                handle: None,
                _type: Some(NfChainType::Filter),
                hook: Some(NfHook::Forward),
                prio: None,
                dev: None,
                policy: Some(NfChainPolicy::Accept),
            }))),
        ],
    };
    let json = json!({"nftables":[{"add":{"table":{"family":"inet","name":"some_inet_table"}}},{"add":{"chain":{"family":"inet","table":"some_inet_table","name":"some_inet_chain","type":"filter","hook":"forward","policy":"accept"}}}]});
    println!("{}", &json);
    let parsed: Nftables = serde_json::from_value(json).unwrap();
    assert_eq!(expected, parsed);
}
```

## License

Licensed under either of

* Apache License, Version 2.0
  ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license
  ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

## Maintainers

This project is currently maintained by the following developers:

|       Name       |      Email Address     |                GitHub Username               |
|:----------------:|:----------------------:|:--------------------------------------------:|
| Jasper Wiegratz  | wiegratz@uni-bremen.de |       [@jwhb](https://github.com/jwhb)       |

