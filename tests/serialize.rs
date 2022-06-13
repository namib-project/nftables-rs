use nft::{expr::*, schema::*, stmt::*, types::*};

#[test]
fn test_serialize() {
    let _a: Nftables = Nftables {
        objects: vec![
            NfObject::CmdObject(NfCmd::Add(NfListObject::Table(Table {
                family: NfFamily::INet,
                name: "namib".to_string(),
                handle: None,
            }))),
            NfObject::CmdObject(NfCmd::Add(NfListObject::Chain(Chain {
                family: NfFamily::INet,
                table: "namib".to_string(),
                name: "one_chain".to_string(),
                newname: None,
                handle: None,
                _type: Some(NfChainType::Filter),
                hook: Some(NfHook::Forward),
                prio: None,
                dev: None,
                policy: Some(NfChainPolicy::Accept),
            }))),
            NfObject::CmdObject(NfCmd::Add(NfListObject::Rule(Rule {
                family: NfFamily::INet,
                table: "namib".to_string(),
                chain: "one_chain".to_string(),
                expr: vec![
                    Statement::Match(Match {
                        left: Expression::List(vec![
                            Expression::Number(123),
                            Expression::String("asd".to_string()),
                        ]),
                        right: Expression::Named(NamedExpression::CT(CT {
                            key: "state".to_string(),
                            family: None,
                            dir: None,
                        })),
                        op: Operator::EQ,
                    }),
                    Statement::Drop(Some(Drop {})),
                ],
                handle: None,
                index: None,
                comment: None,
            }))),
        ],
    };

    let j = serde_json::to_string(&_a).unwrap();
    let result: Nftables = serde_json::from_str(&j).unwrap();
    println!("JSON: {}", j);
    println!("Parsed: {:?}", result);
}
