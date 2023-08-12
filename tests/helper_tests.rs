use nftables::{batch::Batch, expr, helper, schema, types};

#[test]
#[ignore]
/// Reads current ruleset from nftables and reads it to `Nftables` Rust struct.
fn test_list_ruleset() {
    helper::get_current_ruleset(None, None).unwrap();
}

#[test]
#[ignore]
/// Applies a ruleset to nftables.
fn test_apply_ruleset() {
    let ruleset = example_ruleset();
    nftables::helper::apply_ruleset(&ruleset, None, None).unwrap();
}

fn example_ruleset() -> schema::Nftables {
    let mut batch = Batch::new();
    let table_name = "test-table-01".to_string();
    batch.add(schema::NfListObject::Table(schema::Table::new(
        types::NfFamily::IP,
        table_name.clone(),
    )));
    // create named set
    let set_name = "test_set".to_string();
    batch.add(schema::NfListObject::Set(schema::Set {
        family: types::NfFamily::IP,
        table: table_name.clone(),
        name: set_name.clone(),
        handle: None,
        set_type: schema::SetTypeValue::Single(schema::SetType::Ipv4Addr),
        policy: None,
        flags: None,
        elem: None,
        timeout: None,
        gc_interval: None,
        size: None,
    }));
    // add element to set
    batch.add(schema::NfListObject::Element(schema::Element {
        family: types::NfFamily::IP,
        table: table_name,
        name: set_name,
        elem: vec![
            expr::Expression::String("127.0.0.1".to_string()),
            expr::Expression::String("127.0.0.2".to_string()),
        ],
    }));
    batch.delete(schema::NfListObject::Table(schema::Table::new(
        types::NfFamily::IP,
        "test-table-01".to_string(),
    )));
    batch.to_nftables()
}
