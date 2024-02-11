#[macro_export]
macro_rules! nft {
    (@some_or_none) => { None };
    (@some_or_none null) => { None };
    (@some_or_none $entity:literal) => { Some($entity) };
    (@some_or_none $entity:ident) => { Some(stringify!($entity).to_string()) };

    // Helper macro for creating an NfChainPolicy from an identifier
    (@nfchainpolicy $policy:ident) => {
        <nftables::types::NfChainPolicy as std::str::FromStr>::from_str(stringify!($policy))
            .expect("Could not match NfChainPolicy")
    };
    (@some_nfchainpolicy) => { None };
    (@some_nfchainpolicy null) => { None };
    (@some_nfchainpolicy $policy:ident) => { Some(nft!(@nfchainpolicy $policy)) };

    // Helper macro for creating an NfChainType from an identifier
    (@nfchaintype $type:ident) => {
        <nftables::types::NfChainType as std::str::FromStr>::from_str(stringify!($type))
            .expect("Could not match NfChainType")
    };
    (@some_nfchaintype) => { None };
    (@some_nfchaintype null) => { None };
    (@some_nfchaintype $type:ident) => { Some(nft!(@nfchaintype $type)) };

    // Helper macro for creating an NfHook from an identifier
    (@nfhook $hook:ident) => {
        <nftables::types::NfHook as std::str::FromStr>::from_str(stringify!($hook))
            .expect("Could not match NfHook")
    };
    (@some_nfhook) => { None };
    (@some_nfhook null) => { None };
    (@some_nfhook $hook:ident) => { Some(nft!(@nfhook $hook)) };

    // Helper macro for creating an NfFamily from an identifier
    (@nffamily $family:ident) => {
        <nftables::types::NfFamily as std::str::FromStr>::from_str(stringify!($family))
            .expect("Could not match NfFamily")
    };

    // Helper macro for converting an identifier to a String
    (@to_str $str:ident) => {
        stringify!($str).to_string()
    };

    // Macro arm for table
    (table $family:ident $name:ident) => {
        nftables::schema::Table {
            family: nft!(@nffamily $family),
            name: nft!(@to_str $name),
            handle: None,
        }
    };

    // Macro arm for chain
    (chain $family:ident $table:ident $name:ident $( { type $type:ident hook $hook:ident device $device:ident priority $priority:tt ; policy $policy:ident } )? ) => {
        nftables::schema::Chain {
            family: nft!(@nffamily $family),
            table: nft!(@to_str $table),
            name: nft!(@to_str $name),
            newname: None,
            handle: None,
            _type: nft!(@some_nfchaintype $($type)?),
            hook: nft!(@some_nfhook $($hook)?),
            prio: nft!(@some_or_none $($priority)?),
            dev: nft!(@some_or_none $($device)?),
            policy: nft!(@some_nfchainpolicy$($policy)?),
        }
    };

}
