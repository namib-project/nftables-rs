use std::collections::HashSet;

use crate::{expr::Expression, stmt::Statement, types::*};

use serde::{Deserialize, Serialize};

use crate::visitor::single_string_to_vec;

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
    ListObject(NfListObject),
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
pub enum FlushObject {
    Table(Table),
    Chain(Chain),
    Set(Set),
    Map(Map),
    Meter(Meter),
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
    #[serde(rename = "type", deserialize_with = "single_string_to_vec")]
    pub set_type: Vec<String>,
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
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Map {
    // TODO
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SetPolicy {
    Performance,
    Memory,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "lowercase")]
pub enum SetFlag {
    Constant,
    Interval,
    Timeout,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
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
pub struct FlowTable {
    pub family: String,
    pub table: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<u32>,
    pub hook: Option<NfHook>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prio: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
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

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
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
