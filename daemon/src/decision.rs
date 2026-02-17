use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::{oneshot, RwLock};

use crate::config::Config;
use crate::exclusions::ExclusionList;
use crate::process_info::ProcessInfoCache;
use crate::rules::{Action, RuleStore};

/// A pending permission request waiting for a user decision.
#[derive(Debug)]
pub struct PendingRequest {
    pub request_id: u64,
    pub pid: i32,
    pub executable: String,
    pub target_path: String,
    pub access_type: String,
    pub app_name: String,
    pub timestamp: u64,
    pub response_tx: oneshot::Sender<UserDecision>,
}

/// The user's decision from the UI or CLI.
#[derive(Debug, Clone)]
pub struct UserDecision {
    pub action: Action,
    pub duration: String,
    pub path_scope: String,
    pub permission: String,
}

/// The decision engine state.
pub struct DecisionEngine {
    pub config: Arc<RwLock<Config>>,
    pub rules: Arc<RuleStore>,
    pub exclusions: Arc<RwLock<ExclusionList>>,
    pub process_cache: Arc<ProcessInfoCache>,
    pub pending_requests: Arc<RwLock<HashMap<u64, PendingRequest>>>,
}

impl DecisionEngine {
    pub fn new(
        config: Arc<RwLock<Config>>,
        rules: Arc<RuleStore>,
        exclusions: Arc<RwLock<ExclusionList>>,
        process_cache: Arc<ProcessInfoCache>,
    ) -> Self {
        Self {
            config,
            rules,
            exclusions,
            process_cache,
            pending_requests: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}
