//trace_macros!(true);

use nftables_dsl::nft;

#[test]
fn test_dsl() {
    assert_eq!(
        nft!(table arp lowlevel),
        nftables::schema::Table {
            family: nftables::types::NfFamily::ARP,
            name: "lowlevel".to_string(),
            handle: None,
        }
    );
    assert_eq!(
        nft!(chain inet filter foobar),
        nftables::schema::Chain {
            family: nftables::types::NfFamily::INet,
            table: "filter".to_string(),
            name: "foobar".to_string(),
            newname: None,
            handle: None,
            _type: None,
            hook: None,
            prio: None,
            dev: None,
            policy: None,
        }
    );
    assert_eq!(
        nft!(chain ip foo input { type filter hook input device eth0 priority 300 ; policy accept}),
        nftables::schema::Chain {
            family: nftables::types::NfFamily::IP,
            table: "foo".to_string(),
            name: "input".to_string(),
            newname: None,
            handle: None,
            _type: Some(nftables::types::NfChainType::Filter),
            hook: Some(nftables::types::NfHook::Input),
            prio: Some(300),
            dev: Some("eth0".to_string()),
            policy: Some(nftables::types::NfChainPolicy::Accept),
        }
    );
    assert_eq!(
        nft!(chain ip foo input { type null hook null device null priority null ; policy null }),
        nftables::schema::Chain {
            family: nftables::types::NfFamily::IP,
            table: "foo".to_string(),
            name: "input".to_string(),
            newname: None,
            handle: None,
            _type: None,
            hook: None,
            prio: None,
            dev: None,
            policy: None,
        }
    );
}
