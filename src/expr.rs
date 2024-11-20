use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::stmt::{Counter, JumpTarget, Statement};

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
/// Expressions are the building blocks of (most) [statements](crate::stmt::Statement).
/// In their most basic form, they are just immediate values represented as a
/// JSON string, integer or boolean type.
pub enum Expression {
    // immediates
    /// A string expression (*immediate expression*).
    /// For string expressions there are two special cases:
    ///   * `@STRING`: The remaining part is taken as [set](crate::schema::Set)
    ///     name to create a set reference.
    ///   * `\*`: Construct a wildcard expression.
    String(String),
    /// An integer expression (*immediate expression*).
    Number(u32),
    /// A boolean expression (*immediate expression*).
    Boolean(bool),
    /// List expressions are constructed by plain arrays containing of an arbitrary number of expressions.
    List(Vec<Expression>),
    /// A [binary operation](BinaryOperation) expression.
    BinaryOperation(BinaryOperation),
    /// Construct a range of values.
    ///
    /// The first array item denotes the lower boundary, the second one the upper boundary.
    Range(Range),

    /// Wrapper for non-immediate expressions.
    Named(NamedExpression),
    /// A verdict expression (used in [verdict maps](crate::stmt::VerdictMap)).
    Verdict(Verdict),
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
/// Wrapper for non-immediate [Expressions](Expression).
pub enum NamedExpression {
    /// Concatenate several expressions.
    Concat(Vec<Expression>),
    /// This object constructs an anonymous set with [items](SetItem).
    /// For mappings, an array of arrays with exactly two elements is expected.
    Set(Vec<SetItem>),
    /// Map a key to a value.
    Map(Box<Map>),
    /// Construct an IPv4 or IPv6 [prefix](Prefix) consisting of address part and prefix length.
    Prefix(Prefix),

    /// Construct a [payload](Payload) expression, i.e. a reference to a certain part of packet data.
    Payload(Payload),

    /// Create a reference to a field in an IPv6 extension header.
    Exthdr(Exthdr),
    #[serde(rename = "tcp option")]
    /// Create a reference to a field of a TCP option header.
    TcpOption(TcpOption),
    #[serde(rename = "sctp chunk")]
    /// Create a reference to a field of an SCTP chunk.
    SctpChunk(SctpChunk),
    // TODO: DCCP Option
    /// Create a reference to packet meta data.
    Meta(Meta),
    /// Create a reference to packet routing data.
    RT(RT),
    /// Create a reference to packet conntrack data.
    CT(CT),
    /// Create a number generator.
    Numgen(Numgen),
    /// Hash packet data (Jenkins Hash).
    JHash(JHash),
    /// Hash packet data (Symmetric Hash).
    SymHash(SymHash),

    /// Perform kernel Forwarding Information Base lookups.
    Fib(Fib),
    /// Explicitly set element object, in case `timeout`, `expires` or `comment`
    /// are desired.
    Elem(Elem),
    /// Construct a reference to packet’s socket.
    Socket(Socket),
    /// Perform OS fingerprinting.
    /// This expression is typically used in the LHS of a [match](crate::stmt::Match) statement.
    Osf(Osf),
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename = "map")]
/// Map a key to a value.
pub struct Map {
    /// Map key.
    pub key: Expression,
    /// Mapping expression consisting of value/target pairs.
    pub data: Expression,
}

/// Default map expression (`true -> true`).
impl Default for Map {
    fn default() -> Self {
        Map {
            key: Expression::Boolean(true),
            data: Expression::Boolean(false),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
/// Item in an anonymous set.
pub enum SetItem {
    /// A set item containing a single expression.
    Element(Expression),
    /// A set item mapping two expressions.
    Mapping(Expression, Expression),
    /// A set item mapping an expression to a statement.
    MappingStatement(Expression, Statement),
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename = "prefix")]
/// Construct an IPv4 or IPv6 prefix consisting of address part in `addr` and prefix length in `len`.
pub struct Prefix {
    /// An IPv4 or IPv6 address.
    pub addr: Box<Expression>,
    /// A prefix length.
    pub len: u32,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename = "range")]
/// Construct a range of values.
pub struct Range {
    /// The range boundaries.
    /// The first array item denotes the lower boundary, the second one the upper boundary.
    pub range: Vec<Expression>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
/// Construct a payload expression, i.e. a reference to a certain part of packet data.
pub enum Payload {
    /// Creates a raw payload expression to point at a random number of bytes at
    /// a certain offset from a given reference point.
    PayloadField(PayloadField),
    /// Allows one to reference a field by name in a named packet header.
    PayloadRaw(PayloadRaw),
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
/// Creates a raw payload expression to point at a random number (`len`) of
/// bytes at a certain offset (`offset`) from a given reference point (`base`).
pub struct PayloadRaw {
    /// The (protocol layer) reference point.
    pub base: PayloadBase,
    /// Offset from the reference point.
    pub offset: u32,
    /// Number of bytes.
    pub len: u32,
}

/// Default raw payload expression (0-length at link layer).
impl Default for PayloadRaw {
    fn default() -> Self {
        PayloadRaw {
            base: PayloadBase::LL,
            offset: 0,
            len: 0,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
/// Construct a payload expression, i.e. a reference to a certain part of packet data.
/// Allows to reference a field by name (`field`) in a named packet header (`protocol`).
pub struct PayloadField {
    /// A named packet header.
    pub protocol: String,
    /// The field name.
    pub field: String,
}

/// Default payload field reference (`arp ptype`).
impl Default for PayloadField {
    fn default() -> Self {
        PayloadField {
            protocol: "arp".to_string(),
            field: "ptype".to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
/// Represents a protocol layer for [payload](Payload) references.
pub enum PayloadBase {
    /// Link layer, for example the Ethernet header.
    LL,
    /// Network header, for example IPv4 or IPv6.
    NH,
    /// Transport Header, for example TCP.
    /// *Added in nftables 0.9.2 and Linux kernel 5.3.*
    TH,
    /// Inner Header / Payload, i.e. after the L4 transport level header.
    ///
    /// *Added in Kernel version 6.2.*
    IH,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename = "exthdr")]
/// Create a reference to a field (field) in an IPv6 extension header (name).
/// `offset` is used only for `rt0` protocol.
pub struct Exthdr {
    /// The IPv6 extension header name.
    pub name: String,
    /// The field name.
    ///
    /// If the `field` property is not given, the expression is to be used as a
    /// header existence check in a match statement with a boolean on the right
    /// hand side.
    pub field: Option<String>,
    /// The offset length. Used only for `rt0` protocol.
    pub offset: Option<u32>,
}

/// Default extension header reference to `hbh` (Hop-by-Hop) field.
impl Default for Exthdr {
    fn default() -> Self {
        Exthdr {
            name: "hbh".to_string(),
            field: None,
            offset: None,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename = "tcp option")]
/// Create a reference to a field of a TCP option header.
pub struct TcpOption {
    /// The TCP option header name.
    pub name: String,
    /// The field name.
    ///
    /// If the field property is not given, the expression is to be used as a
    /// TCP option existence check in a match statement with a boolean on the
    /// right hand side.
    pub field: Option<String>,
}

/// Default TCP option for `maxseg` option.
impl Default for TcpOption {
    fn default() -> Self {
        TcpOption {
            name: "maxseg".to_string(),
            field: None,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename = "sctp chunk")]
/// Create a reference to a field of an SCTP chunk.
pub struct SctpChunk {
    /// The SCTP chunk name.
    pub name: String,
    /// The field name.
    ///
    /// If the field property is not given, the expression is to be used as an
    /// SCTP chunk existence check in a match statement with a boolean on the
    /// right hand side.
    pub field: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename = "meta")]
/// Create a reference to packet meta data.
///
/// See also: <https://wiki.nftables.org/wiki-nftables/index.php/Matching_packet_metainformation>
pub struct Meta {
    /// The packet [meta data key](MetaKey).
    pub key: MetaKey,
}

/// Default impl for meta key `l4proto`.
impl Default for Meta {
    fn default() -> Self {
        Meta {
            key: MetaKey::L4proto,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
/// Represents a `meta` key for packet meta data.
///
/// See also: <https://wiki.nftables.org/wiki-nftables/index.php/Matching_packet_metainformation>
pub enum MetaKey {
    // matching by packet info:
    /// Packet type (unicast, broadcast, multicast, other).
    Pkttype,
    /// Packet length in bytes.
    Length,
    /// Packet protocol / EtherType protocol value.
    Protocol,
    /// Netfilter packet protocol family.
    Nfproto,
    /// Layer 4 protocol.
    L4proto,

    // matching by interface:
    /// Input interface index.
    Iif,
    /// Input interface name.
    Iifname,
    /// Input interface type.
    Iiftype,
    /// Input interface kind name.
    Iifkind,
    /// Input interface group.
    Iifgroup,
    /// Output interface index.
    Oif,
    /// Output interface name.
    Oifname,
    /// Output interface type.
    Oiftype,
    /// Output interface kind name.
    Oifkind,
    /// Output interface group.
    Oifgroup,
    /// Input bridge interface name.
    Ibridgename,
    /// Output bridge interface name.
    Obridgename,
    /// Input bridge interface name
    Ibriport,
    /// Output bridge interface name
    Obriport,

    // matching by packet mark, routing class and realm:
    /// Packet mark.
    Mark,
    /// TC packet priority.
    Priority,
    /// Routing realm.
    Rtclassid,

    // matching by socket uid/gid:
    /// UID associated with originating socket.
    Skuid,
    /// GID associated with originating socket.
    Skgid,

    // matching by security selectors:
    /// CPU number processing the packet.
    Cpu,
    /// Socket control group ID.
    Cgroup,
    /// `true` if packet was ipsec encrypted. (*obsolete*)
    Secpath,

    // matching by miscellaneous selectors:
    /// Pseudo-random number.
    Random,
    /// [nftrace debugging] bit.
    ///
    /// [nftract debugging]: <https://wiki.nftables.org/wiki-nftables/index.php/Ruleset_debug/tracing>
    Nftrace,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename = "rt")]
/// Create a reference to packet routing data.
pub struct RT {
    /// The routing data key.
    pub key: RTKey,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The protocol family.
    ///
    /// The `family` property is optional and defaults to unspecified.
    pub family: Option<RTFamily>,
}

/// Default impl for [RT] with key `nexthop`.
impl Default for RT {
    fn default() -> Self {
        RT {
            key: RTKey::NextHop,
            family: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
/// Represents a key to reference to packet routing data.
pub enum RTKey {
    /// Routing realm.
    ClassId,
    /// Routing nexthop.
    NextHop,
    /// TCP maximum segment size of route.
    MTU,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
/// Represents a protocol family for use by the `ct` expression.
pub enum RTFamily {
    IP,
    IP6,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename = "ct")]
/// Create a reference to packet conntrack data.
pub struct CT {
    /// The conntrack expression.
    ///
    /// See also: *CONNTRACK EXPRESSIONS* in *ntf(8)*.
    pub key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The [conntrack protocol family](CTFamily).
    pub family: Option<CTFamily>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Conntrack flow [direction](CTDir).
    ///
    /// Some CT keys do not support a direction. In this case, `dir` must not be given.
    pub dir: Option<CTDir>,
}

/// Default impl for conntrack with `l3proto` conntrack key.
impl Default for CT {
    fn default() -> Self {
        CT {
            key: "l3proto".to_string(),
            family: None,
            dir: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
/// Represents a protocol family for use by the `ct` expression.
pub enum CTFamily {
    /// IPv4 conntrack protocol family.
    IP,
    /// IPv6 conntrack protocol family.
    IP6,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
/// Represents a direction for use by the `ct` expression.
pub enum CTDir {
    /// Original direction.
    Original,
    /// Reply direction.
    Reply,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename = "numgen")]
/// Create a number generator.
pub struct Numgen {
    /// The [number generator mode](NgMode).
    pub mode: NgMode,
    #[serde(rename = "mod")]
    /// Specifies an upper boundary ("modulus") which is not reached by returned
    /// numbers.
    pub ng_mod: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Allows one to increment the returned value by a fixed offset.
    pub offset: Option<u32>,
}

/// Default impl for numgen with mode `inc` and mod `7`.
impl Default for Numgen {
    fn default() -> Self {
        Numgen {
            mode: NgMode::Inc,
            ng_mod: 7,
            offset: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
/// Represents a number generator mode.
pub enum NgMode {
    /// The last returned value is simply incremented.
    Inc,
    /// A new random number is returned.
    Random,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename = "jhash")]
/// Hash packet data (Jenkins Hash).
pub struct JHash {
    #[serde(rename = "mod")]
    /// Specifies an upper boundary ("modulus") which is not reached by returned numbers.
    pub hash_mod: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Increment the returned value by a fixed offset.
    pub offset: Option<u32>,
    /// Determines the parameters of the packet header to apply the hashing,
    /// concatenations are possible as well.
    pub expr: Box<Expression>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Specify an init value used as seed in the hashing function
    pub seed: Option<u32>,
}

/// Default impl for JHash
impl Default for JHash {
    fn default() -> Self {
        JHash {
            hash_mod: 7,
            offset: None,
            expr: Box::new(Expression::Named(NamedExpression::Payload(
                Payload::PayloadField(PayloadField {
                    protocol: "ip".to_string(),
                    field: "saddr".to_string(),
                }),
            ))),
            seed: None,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename = "symhash")]
/// Hash packet data (Symmetric Hash).
pub struct SymHash {
    #[serde(rename = "mod")]
    /// Specifies an upper boundary ("modulus") which is not reached by returned numbers.
    pub hash_mod: u32,
    /// Increment the returned value by a fixed offset.
    pub offset: Option<u32>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename = "fib")]
/// Perform kernel Forwarding Information Base lookups.
pub struct Fib {
    pub result: FibResult,
    pub flags: HashSet<FibFlag>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
/// Represents which data is queried by `fib` lookup.
pub enum FibResult {
    Oif,
    Oifname,
    Type,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "lowercase")]
/// Represents flags for `fib` lookup.
pub enum FibFlag {
    /// Consider the source address of a packet.
    Saddr,
    /// Consider the destination address of a packet.
    Daddr,
    /// Consider the packet mark.
    Mark,
    /// Consider the packet's input interface.
    Iif,
    /// Consider the packet's output interface.
    Oif,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
/// Represents a binary operation to be used in an `Expression`.
pub enum BinaryOperation {
    #[serde(rename = "&")]
    /// Binary AND (`&`)
    AND(Box<Expression>, Box<Expression>),

    #[serde(rename = "|")]
    /// Binary OR (`|`)
    OR(Box<Expression>, Box<Expression>),

    #[serde(rename = "^")]
    /// Binary XOR (`^`)
    XOR(Box<Expression>, Box<Expression>),

    #[serde(rename = "<<")]
    /// Left shift (`<<`)
    LSHIFT(Box<Expression>, Box<Expression>),

    #[serde(rename = ">>")]
    /// Right shift (`>>`)
    RSHIFT(Box<Expression>, Box<Expression>),
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
/// Verdict expression.
pub enum Verdict {
    Accept,
    Drop,
    Continue,
    Return,
    Jump(JumpTarget),
    Goto(JumpTarget),
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename = "elem")]
/// Explicitly set element object.
pub struct Elem {
    pub val: Box<Expression>,
    pub timeout: Option<u32>,
    pub expires: Option<u32>,
    pub comment: Option<String>,
    pub counter: Option<Counter>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename = "socket")]
/// Construct a reference to packet’s socket.
pub struct Socket {
    pub key: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename = "osf")]
/// Perform OS fingerprinting.
/// This expression is typically used in the LHS of a `match` statement.
pub struct Osf {
    ///  Name of the OS signature to match.
    /// All signatures can be found at pf.os file.
    /// Use "unknown" for OS signatures that the expression could not detect.
    pub key: String,
    /// Do TTL checks on the packet to determine the operating system.
    pub ttl: OsfTtl,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
/// TTL check mode for `osf`.
pub enum OsfTtl {
    /// Check if the IP header's TTL is less than the fingerprint one. Works for globally-routable addresses.
    Loose,
    /// Do not compare the TTL at all.
    Skip,
}
