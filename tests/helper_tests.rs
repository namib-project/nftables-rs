use nft::{batch::Batch, helper, schema, types};

#[test]
#[ignore]
/// Reads current ruleset from nftables and reads it to `Nftables` Rust struct.
fn test_list_ruleset() {
    helper::get_current_ruleset(None, None);
}

#[test]
#[ignore]
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
