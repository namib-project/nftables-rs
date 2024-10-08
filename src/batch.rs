use serde::{Deserialize, Serialize};

use crate::schema::{NfCmd, NfListObject, NfObject, Nftables};

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
/// Batch manages nftables objects and is used to prepare an nftables payload.
pub struct Batch {
    data: Vec<NfObject>,
}

impl Default for Batch {
    fn default() -> Self {
        Self::new()
    }
}

impl Batch {
    /// Creates an empty Batch instance.
    pub fn new() -> Batch {
        Batch { data: Vec::new() }
    }

    /// Adds object with `add` command to Batch.
    pub fn add(&mut self, obj: NfListObject) {
        self.data.push(NfObject::CmdObject(NfCmd::Add(obj)))
    }

    /// Adds object with `delete` command to Batch.
    pub fn delete(&mut self, obj: NfListObject) {
        self.data.push(NfObject::CmdObject(NfCmd::Delete(obj)))
    }

    /// Adds a command to Batch.
    pub fn add_cmd(&mut self, cmd: NfCmd) {
        self.data.push(NfObject::CmdObject(cmd))
    }

    /// Adds a list object (without a command) directly to Batch.
    /// This corresponds to the descriptive output format of `nft -j list ruleset`.
    pub fn add_obj(&mut self, obj: NfListObject) {
        self.data.push(NfObject::ListObject(Box::new(obj)))
    }

    /// Adds all given objects to the batch.
    pub fn add_all(&mut self, objs: Vec<NfObject>) {
        self.data.extend(objs)
    }

    /// Wraps Batch in nftables object.
    pub fn to_nftables(self) -> Nftables {
        Nftables { objects: self.data }
    }
}
