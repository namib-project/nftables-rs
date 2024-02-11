#[macro_export]
macro_rules! nft {
    (@some_or_none) => { None };
    (@some_or_none $entity:literal) => { Some($entity) };

    // Helper macro for creating an NfChainType from an identifier
    (@chaintype $type:ident) => {
        <nftables::types::NfChainType as std::str::FromStr>::from_str(stringify!($type))
            .expect("Could not match NfChainType")
    };

    // Helper macro for creating an NfHook from an identifier
    (@nfhook $hook:ident) => {
        <nftables::types::NfHook as std::str::FromStr>::from_str(stringify!($hook))
            .expect("Could not match NfHook")
    };
    (@some_nfhook) => { None };
    (@some_nfhook $hook:ident) => { Some(nft!(@nfhook $hook)) };

    // Helper macro for creating an NfFamily from an identifier
    (@nffamily $family:ident) => {
        <nftables::types::NfFamily as std::str::FromStr>::from_str(stringify!($family))
            .expect("Could not match NfFamily")
    };

    // Helper macro for converting an identifier to a String
    (@name $name:ident) => {
        stringify!($name).to_string()
    };

    // Macro arm for table
    (table $family:ident $name:ident) => {
        nftables::schema::Table {
            family: nft!(@nffamily $family),
            name: nft!(@name $name),
            handle: None,
        }
    };

    // Macro arm for chain
    (chain $family:ident $table:ident $name:ident $( { type $type:ident hook $hook:ident priority $priority:literal ; } )? ) => {
        nftables::schema::Chain {
            family: nft!(@nffamily $family),
            table: nft!(@name $table),
            name: nft!(@name $name),
            newname: None,
            handle: None,
            _type: None, //$(Some(nft!(@chaintype $type)))?,
            hook: nft!(@some_nfhook $($hook)?), // (Some(nft!(@nfhook $hook)))?,
            prio: nft!(@some_or_none $($priority)?),
            dev: None,
            policy: None,
        }
    };

}
