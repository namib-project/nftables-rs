use serde::{Deserialize, Serialize};

/// Families in nftables.
///
/// See <https://wiki.nftables.org/wiki-nftables/index.php/Nftables_families>.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NfFamily {
    IP,
    IP6,
    INet,
    ARP,
    Bridge,
    NetDev,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
/// Represents the type of a Chain.
pub enum NfChainType {
    Filter,
    Route,
    NAT,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
/// Represents the policy of a Chain.
pub enum NfChainPolicy {
    Accept,
    Drop,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
/// Represents a netfilter hook.
///
/// See <https://wiki.nftables.org/wiki-nftables/index.php/Netfilter_hooks>.
pub enum NfHook {
    Ingress,
    Prerouting,
    Forward,
    Input,
    Output,
    Postrouting,
    Egress,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
/// Represents a conntrack helper protocol.
pub enum CTHProto {
    TCP,
    UDP,
    DCCP,
    SCTP,
    GRE,
    ICMPv6,
    ICMP,
    Generic,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum RejectCode {
    #[serde(rename = "admin-prohibited")]
    /// Host administratively prohibited (ICMPX, ICMP, ICMPv6)
    AdminProhibited,
    #[serde(rename = "port-unreachable")]
    /// Destination port unreachable (ICMPX, ICMP, ICMPv6)
    PortUnreach,
    #[serde(rename = "no-route")]
    /// No route to destination (ICMPX, ICMP, ICMPv6)
    NoRoute,
    #[serde(rename = "host-unreachable")]
    /// Destination host unreachable (ICMPX, ICMP, ICMPv6)
    HostUnreach,
    #[serde(rename = "net-unreachable")]
    /// Destination network unreachable (ICMP)
    NetUnreach,
    #[serde(rename = "prot-unreachable")]
    /// Destination protocol unreachable (ICMP)
    ProtUnreach,
    #[serde(rename = "net-prohibited")]
    /// Network administratively prohibited (ICMP)
    NetProhibited,
    #[serde(rename = "host-prohibited")]
    /// Host administratively prohibited (ICMP)
    HostProhibited,
    #[serde(rename = "addr-unreachable")]
    /// Address unreachable (ICMPv6)
    AddrUnreach,
}
