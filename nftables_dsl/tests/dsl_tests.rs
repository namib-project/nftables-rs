//trace_macros!(true);

use std::str::FromStr;

use nftables::types::NfChainType;
use nftables_dsl::nft;


#[test]
fn test_dsl() {
  println!("{:?}", NfChainType::from_str("filter"));
  println!("{:?}", nft!(table arp lowlevel));
  println!("{:?}", nft!(chain inet filter foobar));
  println!("{:?}", nft!(chain ip foo input { type filter hook input priority 0 ; }));
}
