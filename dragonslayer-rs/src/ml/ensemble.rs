//! Ensemble Predictor
//!
//! Combines multiple classifiers for improved accuracy.

use std::collections::HashMap;
use super::classifier::{ClassificationResult, PatternClassifier};

/// Ensemble configuration
#[derive(Debug, Clone)]
pub struct EnsembleConfig {
    /// Voting strategy
    pub voting_strategy: VotingStrategy,
    
    /// Number of base classifiers
    pub num_classifiers: usize,
}

/// Voting strategy for ensemble
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VotingStrategy {
    /// Majority voting
    Majority,
    /// Weighted voting
    Weighted,
    /// Average confidence
    Average,
}

impl Default for EnsembleConfig {
    fn default() -> Self {
        Self {
            voting_strategy: VotingStrategy::Weighted,
            num_classifiers: 3,
        }
    }
}

/// Ensemble predictor
pub struct EnsemblePredictor {
    /// Base classifiers
    classifiers: Vec<PatternClassifier>,
    
    /// Configuration
    config: EnsembleConfig,
    
    /// Classifier weights (for weighted voting)
    weights: Vec<f64>,
}

impl EnsemblePredictor {
    /// Create a new ensemble
    pub fn new() -> Self {
        let config = EnsembleConfig::default();
        Self {
            classifiers: vec![PatternClassifier::new(); config.num_classifiers],
            weights: vec![1.0 / config.num_classifiers as f64; config.num_classifiers],
            config,
        }
    }
    
    /// Create with configuration
    pub fn with_config(config: EnsembleConfig) -> Self {
        Self {
            classifiers: vec![PatternClassifier::new(); config.num_classifiers],
            weights: vec![1.0 / config.num_classifiers as f64; config.num_classifiers],
            config,
        }
    }
    
    /// Predict using ensemble
    pub fn predict(&self, features: &[f64]) -> crate::core::error::Result<ClassificationResult> {
        // Get predictions from all classifiers
        let mut predictions = Vec::new();
        
        for classifier in &self.classifiers {
            match classifier.classify(features) {
                Ok(pred) => predictions.push(pred),
                Err(_) => continue,
            }
        }
        
        if predictions.is_empty() {
            return Err(crate::core::error::DragonError::MachineLearning(
                "No valid predictions".to_string()
            ));
        }
        
        // Aggregate predictions based on voting strategy
        match self.config.voting_strategy {
            VotingStrategy::Majority => self.majority_vote(&predictions),
            VotingStrategy::Weighted => self.weighted_vote(&predictions),
            VotingStrategy::Average => self.average_confidence(&predictions),
        }
    }
    
    /// Majority voting
    fn majority_vote(&self, predictions: &[ClassificationResult]) -> crate::core::error::Result<ClassificationResult> {
        let mut votes = HashMap::new();
        
        for pred in predictions {
            *votes.entry(pred.predicted_class.clone()).or_insert(0) += 1;
        }
        
        let (class, _) = votes.iter()
            .max_by_key(|(_, count)| *count)
            .ok_or_else(|| crate::core::error::DragonError::MachineLearning("No votes".to_string()))?;
        
        Ok(ClassificationResult {
            predicted_class: class.clone(),
            confidence: predictions[0].confidence,
            probabilities: predictions[0].probabilities.clone(),
            features: predictions[0].features.clone(),
        })
    }
    
    /// Weighted voting
    fn weighted_vote(&self, predictions: &[ClassificationResult]) -> crate::core::error::Result<ClassificationResult> {
        let mut weighted_scores = HashMap::new();
        
        for (i, pred) in predictions.iter().enumerate() {
            let weight = self.weights[i];
            for (class, prob) in &pred.probabilities {
                let entry = weighted_scores.entry(class.clone()).or_insert(0.0);
                *entry += prob * weight;
            }
        }
        
        let (class, confidence) = weighted_scores.iter()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap())
            .ok_or_else(|| crate::core::error::DragonError::MachineLearning("No weighted votes".to_string()))?;
        
        Ok(ClassificationResult {
            predicted_class: class.clone(),
            confidence: *confidence,
            probabilities: weighted_scores.clone(),
            features: predictions[0].features.clone(),
        })
    }
    
    /// Average confidence
    fn average_confidence(&self, predictions: &[ClassificationResult]) -> crate::core::error::Result<ClassificationResult> {
        let avg_confidence: f64 = predictions.iter()
            .map(|p| p.confidence)
            .sum::<f64>() / predictions.len() as f64;
        
        Ok(ClassificationResult {
            predicted_class: predictions[0].predicted_class.clone(),
            confidence: avg_confidence,
            probabilities: predictions[0].probabilities.clone(),
            features: predictions[0].features.clone(),
        })
    }
}

impl Default for EnsemblePredictor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ensemble_creation() {
        let ensemble = EnsemblePredictor::new();
        assert_eq!(ensemble.classifiers.len(), 3);
    }
    
    #[test]
    fn test_ensemble_prediction() {
        let ensemble = EnsemblePredictor::new();
        let features = vec![1.0, 2.0, 3.0];
        
        let result = ensemble.predict(&features).unwrap();
        assert!(!result.probabilities.is_empty());
    }
}

