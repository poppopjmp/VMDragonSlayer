//! Enterprise Features for DragonSlayer-RS
//!
//! Provides HIPAA compliance, enterprise security, and integration capabilities.

pub mod compliance;
pub mod security;
pub mod integration;

pub use compliance::*;
pub use security::*;
pub use integration::*;

// Re-export key types at module level
pub use compliance::{HIPAAComplianceManager, AuditLogEntry, AuditEventType, AuditResult};

