use std::collections::HashSet;

use crate::{expr::Expression, stmt::Statement, types::*, visitor::single_string_to_option_vec};

use serde::{Deserialize, Serialize};

use strum_macros::EnumString;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Nftables {
    // "nftables"
    #[serde(rename = "nftables")]
    pub objects: Vec<NfObject>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum NfObject {
    // OBJECTS
    CmdObject(NfCmd),
    ListObject(Box<NfListObject>),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NfListObject {
    // LIST_OBJECT
    Table(Table),
    Chain(Chain),
    Rule(Rule),
    Set(Set),
    Map(Map),
    Element(Element),
    FlowTable(FlowTable),
    Counter(Counter),
    Quota(Quota),
    #[serde(rename = "ct helper")]
    CTHelper(CTHelper),
    Limit(Limit),
    #[serde(rename = "metainfo")]
    MetainfoObject(MetainfoObject),
    CTTimeout(CTTimeout),
    #[serde(rename = "ct expectation")]
    CTExpectation(CTExpectation),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NfCmd {
    Add(NfListObject), // TODO: CT_*
    Replace(Rule),
    Create(NfListObject), // TODO: ADD_OBJECT
    Insert(NfListObject),
    Delete(NfListObject), // TODO: ADD_OBJECT
    List(NfListObject),
    Reset(ResetObject),
    Flush(FlushObject),
    Rename(Chain),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResetObject {
    Counter(Counter),
    Counters(Vec<Counter>),
    Quota(Quota),
    Quotas(Vec<Quota>),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
/// Empty contents in given object, e.g. remove all chains from given table or remove all elements from given set.
pub enum FlushObject {
    Table(Table),
    Chain(Chain),
    Set(Set),
    Map(Map),
    Meter(Meter),
    Ruleset(Option<Ruleset>),
}

// Ruleset Elements

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Table {
    pub family: NfFamily,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<u32>,
}

impl Table {
    pub fn new(family: NfFamily, name: String) -> Table {
        Table {
            family,
            name,
            handle: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Chain {
    pub family: NfFamily,
    pub table: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub newname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "type")]
    pub _type: Option<NfChainType>, // type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hook: Option<NfHook>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prio: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dev: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<NfChainPolicy>,
}

#[allow(clippy::too_many_arguments)]
impl Chain {
    pub fn new(
        family: NfFamily,
        table: String,
        name: String,
        _type: Option<NfChainType>,
        hook: Option<NfHook>,
        prio: Option<i32>,
        dev: Option<String>,
        policy: Option<NfChainPolicy>,
    ) -> Chain {
        Chain {
            family,
            table,
            name,
            newname: None,
            handle: None,
            _type,
            hook,
            prio,
            dev,
            policy,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Rule {
    pub family: NfFamily,
    pub table: String,
    pub chain: String,
    pub expr: Vec<Statement>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

impl Rule {
    pub fn new(family: NfFamily, table: String, chain: String, expr: Vec<Statement>) -> Rule {
        Rule {
            family,
            table,
            chain,
            expr,
            handle: None,
            index: None,
            comment: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Set {
    pub family: NfFamily,
    pub table: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<u32>,
    #[serde(rename = "type")]
    pub set_type: SetTypeValue,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<SetPolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flags: Option<HashSet<SetFlag>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elem: Option<Vec<Expression>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,
    #[serde(rename = "gc-interval", skip_serializing_if = "Option::is_none")]
    pub gc_interval: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Map {
    pub family: NfFamily,
    pub table: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<u32>,
    #[serde(rename = "type")]
    pub set_type: SetTypeValue,
    pub map: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<SetPolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flags: Option<HashSet<SetFlag>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elem: Option<Vec<Expression>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,
    #[serde(rename = "gc-interval", skip_serializing_if = "Option::is_none")]
    pub gc_interval: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
/// Wrapper for single or concatenated set types.
/// The set type might be a string, such as "ipv4_addr" or an array consisting of strings (for concatenated types).
pub enum SetTypeValue {
    Single(SetType),
    Concatenated(Vec<SetType>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, EnumString)]
#[serde(rename_all = "lowercase")]
/// Describes a set’s datatype.
pub enum SetType {
    // ipv4_addr, ipv6_addr, ether_addr, inet_proto, inet_service, mark
    #[serde(rename = "ipv4_addr")]
    #[strum(serialize = "ipv4_addr")]
    Ipv4Addr,
    #[serde(rename = "ipv6_addr")]
    #[strum(serialize = "ipv6_addr")]
    Ipv6Addr,
    #[serde(rename = "ether_addr")]
    #[strum(serialize = "ether_addr")]
    EtherAddr,
    #[serde(rename = "inet_proto")]
    #[strum(serialize = "inet_proto")]
    InetProto,
    #[serde(rename = "inet_service")]
    #[strum(serialize = "inet_service")]
    InetService,
    #[serde(rename = "mark")]
    #[strum(serialize = "mark")]
    Mark,
    #[serde(rename = "ifname")]
    #[strum(serialize = "ifname")]
    Ifname,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
/// Describes a set’s policy.
pub enum SetPolicy {
    Performance,
    Memory,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "lowercase")]
/// Describes a set’s flags.
pub enum SetFlag {
    Constant,
    Interval,
    Timeout,
    Dynamic,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
/// Describes an operator on set.
pub enum SetOp {
    Add,
    Update,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Element {
    pub family: NfFamily,
    pub table: String,
    pub name: String,
    pub elem: Vec<Expression>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
/// Flowtables allow you to accelerate packet forwarding in software (and in hardware if your NIC supports it)
/// by using a conntrack-based network stack bypass.
pub struct FlowTable {
    /// Family the FlowTable is addressed by.
    pub family: NfFamily,
    /// Table the FlowTable is addressed by.
    pub table: String,
    /// Name the FlowTable is addressed by.
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Handle of the FlowTable object in the current ruleset.
    pub handle: Option<u32>,
    /// Hook the FlowTable resides in.
    pub hook: Option<NfHook>,
    /// The *priority* can be a signed integer or *filter* which stands for 0.
    /// Addition and subtraction can be used to set relative priority, e.g., filter + 5 is equal to 5.
    pub prio: Option<u32>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "single_string_to_option_vec"
    )]
    /// The *devices* are specified as iifname(s) of the input interface(s) of the traffic that should be offloaded.
    /// Devices are required for both traffic directions.
    pub dev: Option<Vec<String>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Counter {
    pub family: String,
    pub table: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub packets: Option<u32>,
    pub bytes: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Quota {
    pub family: String,
    pub table: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub used: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inv: Option<bool>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename = "ct helper")]
/// Enable the specified conntrack helper for this packet.
pub struct CTHelper {
    pub family: String,
    pub table: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<u32>,
    #[serde(rename = "type")]
    pub _type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub l3proto: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Limit {
    pub family: String,
    pub table: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub per: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub burst: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<LimitUnit>,
    pub inv: Option<bool>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LimitUnit {
    Packets,
    Bytes,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Meter {
    pub name: String,
    pub key: Expression,
    pub stmt: Statement,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Ruleset {}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct MetainfoObject {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub json_schema_version: Option<u32>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct CTTimeout {
    pub family: NfFamily,
    pub table: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<CTHProto>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub l3proto: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct CTExpectation {
    pub family: NfFamily,
    pub table: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub l3proto: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<CTHProto>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dport: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u32>,
}
