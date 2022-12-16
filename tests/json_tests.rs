use nftables::expr::{Expression, Meta, MetaKey, NamedExpression};
use nftables::stmt::{Match, Operator, Statement};
use nftables::{schema::*, types::*};
use serde_json::json;
use std::fs::{self, File};
use std::io::BufReader;
use std::path::PathBuf;

#[test]
fn test_deserialize_json_files() {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("resources/test/json");
    println!("Loading tests from {}.", d.display());

    for path in fs::read_dir(&d).expect("Unable to list files") {
        let path = path.unwrap();
        println!("Deserializing file: {}", path.path().display());
        let file = File::open(path.path()).expect("Cannot open file");
        let reader = BufReader::new(file);
        let nf: Nftables = serde_json::from_reader(reader).expect("Could not deserialize file");
        println!("Deserialized document: {:?}", nf);
    }
}

#[test]
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

#[test]
fn test_insert() {
    // nft insert rule inet some_inet_table some_inet_chain position 0 iifname "br-lan" oifname "wg_exit" counter accept
    let expected: Nftables = Nftables {
        objects: vec![NfObject::CmdObject(NfCmd::Insert(NfListObject::Rule(
            Rule {
                family: NfFamily::INet,
                table: "some_inet_table".to_string(),
                chain: "some_inet_chain".to_string(),
                expr: vec![
                    Statement::Match(Match {
                        left: Expression::Named(NamedExpression::Meta(Meta {
                            key: MetaKey::Iifname,
                        })),
                        right: Expression::String("br-lan".to_string()),
                        op: Operator::EQ,
                    }),
                    Statement::Match(Match {
                        left: Expression::Named(NamedExpression::Meta(Meta {
                            key: MetaKey::Oifname,
                        })),
                        right: Expression::String("wg_exit".to_string()),
                        op: Operator::EQ,
                    }),
                    Statement::Counter(None),
                    Statement::Accept(None),
                ],
                handle: None,
                index: Some(0),
                comment: None,
            },
        )))],
    };
    let json = json!({"nftables":[{"insert":{"rule":{"family":"inet","table":"some_inet_table","chain":"some_inet_chain","expr":[{"match":{"left":{"meta":{"key":"iifname"}},"right":"br-lan","op":"=="}},{"match":{"left":{"meta":{"key":"oifname"}},"right":"wg_exit","op":"=="}},{"counter":null},{"accept":null}],"index":0,"comment":null}}}]});
    println!("{}", &json);
    let parsed: Nftables = serde_json::from_value(json).unwrap();
    assert_eq!(expected, parsed);
}
