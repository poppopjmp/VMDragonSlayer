//! Enterprise Security Features

use serde::{Deserialize, Serialize};

/// Security policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPolicy {
    /// Policy name
    pub name: String,
    
    /// Policy description
    pub description: String,
    
    /// Rules
    pub rules: Vec<SecurityRule>,
}

/// Security rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityRule {
    /// Rule ID
    pub rule_id: String,
    
    /// Rule type
    pub rule_type: String,
    
    /// Rule configuration
    pub config: String,
}

/// Security policy manager
pub struct SecurityPolicyManager {
    /// Active policies
    policies: Vec<SecurityPolicy>,
}

impl SecurityPolicyManager {
    pub fn new() -> Self {
        Self {
            policies: vec![],
        }
    }
    
    pub fn add_policy(&mut self, policy: SecurityPolicy) {
        self.policies.push(policy);
    }
    
    pub fn get_policies(&self) -> &[SecurityPolicy] {
        &self.policies
    }
}

impl Default for SecurityPolicyManager {
    fn default() -> Self {
        Self::new()
    }
}

