//! Enterprise Integration Features

use serde::{Deserialize, Serialize};

/// Integration configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationConfig {
    /// Integration name
    pub name: String,
    
    /// Integration type
    pub integration_type: IntegrationType,
    
    /// Configuration
    pub config: serde_json::Value,
}

/// Integration type
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum IntegrationType {
    /// REST API integration
    RESTAPI,
    /// Webhook integration
    Webhook,
    /// Database integration
    Database,
    /// Message queue
    MessageQueue,
}

/// Integration manager
pub struct IntegrationManager {
    /// Configured integrations
    integrations: Vec<IntegrationConfig>,
}

impl IntegrationManager {
    pub fn new() -> Self {
        Self {
            integrations: vec![],
        }
    }
    
    pub fn add_integration(&mut self, integration: IntegrationConfig) {
        self.integrations.push(integration);
    }
    
    pub fn get_integrations(&self) -> &[IntegrationConfig] {
        &self.integrations
    }
}

impl Default for IntegrationManager {
    fn default() -> Self {
        Self::new()
    }
}

