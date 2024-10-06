use nftables::expr::{Expression, Meta, MetaKey, NamedExpression};
use nftables::stmt::{Counter, Match, Operator, Queue, Statement};
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
                    Statement::Counter(Counter::Anonymous(None)),
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

#[test]
fn test_parsing_of_queue_without_flags() {
    let expected = Nftables {
        objects: vec![NfObject::ListObject(Box::new(NfListObject::Rule(Rule {
            family: NfFamily::IP,
            table: "test_table".to_string(),
            chain: "test_chain".to_string(),
            expr: vec![
                Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Payload(
                        nftables::expr::Payload::PayloadField(nftables::expr::PayloadField {
                            protocol: "udp".to_string(),
                            field: "dport".to_string(),
                        }),
                    )),
                    right: Expression::Number(20000),
                    op: Operator::EQ,
                }),
                Statement::Queue(Queue {
                    num: Expression::Number(0),
                    flags: None,
                }),
            ],
            handle: Some(2),
            index: None,
            comment: None,
        })))],
    };

    let json = json!({
        "nftables": [
            {
                "rule": {
                    "family": "ip",
                    "table": "test_table",
                    "chain": "test_chain",
                    "handle": 2,
                    "expr": [
                    {
                        "match": {
                            "op": "==",
                            "left": {
                                "payload": {
                                    "protocol": "udp",
                                    "field": "dport"
                                }
                            },
                            "right": 20000
                        }
                    },
                    {
                        "queue": {
                            "num": 0
                        }
                    }
                ]
                }
            }
        ]
    });

    let parsed: Nftables = serde_json::from_value(json).unwrap();
    assert_eq!(expected, parsed);
}

#[test]
fn test_queue_json_serialisation() {
    let queue = Statement::Queue(Queue {
        num: Expression::Number(0),
        flags: None,
    });

    let expected_json = String::from(r#"{"queue":{"num":0}}"#);
    assert_eq!(expected_json, serde_json::to_string(&queue).unwrap());
}

#[test]
fn test_parse_payload() {
    let expected = Nftables {
        objects: vec![NfObject::ListObject(Box::new(NfListObject::Rule(Rule {
            family: NfFamily::IP,
            table: "test_table".to_string(),
            chain: "test_chain".to_string(),
            expr: vec![
                Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Payload(
                        nftables::expr::Payload::PayloadField(nftables::expr::PayloadField {
                            protocol: "udp".to_string(),
                            field: "dport".to_string(),
                        }),
                    )),
                    right: Expression::Number(20000),
                    op: Operator::EQ,
                }),
                Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Payload(
                        nftables::expr::Payload::PayloadRaw(nftables::expr::PayloadRaw {
                            base: nftables::expr::PayloadBase::TH,
                            offset: 10,
                            len: 4,
                        }),
                    )),
                    right: Expression::Number(20),
                    op: Operator::EQ,
                }),
            ],
            handle: Some(2),
            index: None,
            comment: None,
        })))],
    };

    let json = json!({
        "nftables": [
            {
                "rule": {
                    "family": "ip",
                    "table": "test_table",
                    "chain": "test_chain",
                    "handle": 2,
                    "expr": [
                    {
                        "match": {
                            "op": "==",
                            "left": {
                                "payload": {
                                    "protocol": "udp",
                                    "field": "dport"
                                }
                            },
                            "right": 20000
                        }
                    },
                    {
                        "match": {
                            "op": "==",
                            "left": {
                                "payload": {
                                    "base": "th",
                                    "offset": 10,
                                    "len": 4
                                }
                            },
                            "right": 20
                        }
                    },
                ]
                }
            }
        ]
    });

    let parsed: Nftables = serde_json::from_value(json).unwrap();
    assert_eq!(expected, parsed);
}
