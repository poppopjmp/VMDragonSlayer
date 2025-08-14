# VMDragonSlayer - Advanced VM detection and analysis library
# Copyright (C) 2025 van1sh
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""
Ensemble Predictor
=================

Ensemble learning methods for improved prediction accuracy.
"""

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from sklearn.ensemble import (
    AdaBoostClassifier,
    BaggingClassifier,
    GradientBoostingClassifier,
    RandomForestClassifier,
    VotingClassifier,
)
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import cross_val_score

logger = logging.getLogger(__name__)


@dataclass
class EnsembleConfig:
    """Configuration for ensemble methods"""

    voting_method: str = "soft"  # 'hard' or 'soft'
    n_estimators: int = 100
    max_depth: Optional[int] = None
    random_state: int = 42
    cv_folds: int = 5
    enable_bagging: bool = True
    enable_boosting: bool = True
    enable_voting: bool = True


class EnsemblePredictor:
    """
    Ensemble predictor combining multiple ML models for improved accuracy.

    Features:
    - Voting classifier with multiple base estimators
    - Bagging and boosting methods
    - Cross-validation for model selection
    - Performance evaluation and comparison
    """

    def __init__(self, config: Optional[EnsembleConfig] = None):
        """
        Initialize ensemble predictor.

        Args:
            config: Ensemble configuration
        """
        self.config = config or EnsembleConfig()
        self.logger = logging.getLogger(f"{__name__}.EnsemblePredictor")

        # Ensemble models
        self.voting_classifier = None
        self.bagging_classifier = None
        self.boosting_classifier = None
        self.gradient_boosting = None

        # Performance metrics
        self.scores = {}
        self.best_model = None

        self.logger.info("EnsemblePredictor initialized")

    def create_base_estimators(self) -> List[Tuple[str, Any]]:
        """
        Create base estimators for ensemble methods.

        Returns:
            List of (name, estimator) tuples
        """
        estimators = [
            (
                "rf",
                RandomForestClassifier(
                    n_estimators=self.config.n_estimators,
                    max_depth=self.config.max_depth,
                    random_state=self.config.random_state,
                ),
            ),
            (
                "ada",
                AdaBoostClassifier(
                    n_estimators=self.config.n_estimators,
                    random_state=self.config.random_state,
                ),
            ),
        ]

        return estimators

    def fit(self, X: np.ndarray, y: np.ndarray) -> Dict[str, float]:
        """
        Train ensemble models.

        Args:
            X: Feature matrix
            y: Target labels

        Returns:
            Performance scores for each model
        """
        self.logger.info(f"Training ensemble models on {X.shape[0]} samples")

        results = {}

        # Voting classifier
        if self.config.enable_voting:
            try:
                estimators = self.create_base_estimators()
                self.voting_classifier = VotingClassifier(
                    estimators=estimators, voting=self.config.voting_method
                )
                self.voting_classifier.fit(X, y)

                # Cross-validation score
                cv_scores = cross_val_score(
                    self.voting_classifier, X, y, cv=self.config.cv_folds
                )
                results["voting"] = cv_scores.mean()

                self.logger.info(f"Voting classifier CV score: {cv_scores.mean():.4f}")

            except Exception as e:
                self.logger.error(f"Voting classifier training failed: {e}")
                results["voting"] = 0.0

        # Bagging classifier
        if self.config.enable_bagging:
            try:
                self.bagging_classifier = BaggingClassifier(
                    n_estimators=self.config.n_estimators,
                    random_state=self.config.random_state,
                )
                self.bagging_classifier.fit(X, y)

                cv_scores = cross_val_score(
                    self.bagging_classifier, X, y, cv=self.config.cv_folds
                )
                results["bagging"] = cv_scores.mean()

                self.logger.info(f"Bagging classifier CV score: {cv_scores.mean():.4f}")

            except Exception as e:
                self.logger.error(f"Bagging classifier training failed: {e}")
                results["bagging"] = 0.0

        # Gradient boosting
        if self.config.enable_boosting:
            try:
                self.gradient_boosting = GradientBoostingClassifier(
                    n_estimators=self.config.n_estimators,
                    max_depth=self.config.max_depth,
                    random_state=self.config.random_state,
                )
                self.gradient_boosting.fit(X, y)

                cv_scores = cross_val_score(
                    self.gradient_boosting, X, y, cv=self.config.cv_folds
                )
                results["gradient_boosting"] = cv_scores.mean()

                self.logger.info(f"Gradient boosting CV score: {cv_scores.mean():.4f}")

            except Exception as e:
                self.logger.error(f"Gradient boosting training failed: {e}")
                results["gradient_boosting"] = 0.0

        # Select best model
        if results:
            best_model_name = max(results, key=results.get)
            self.best_model = getattr(
                self, f"{best_model_name}_classifier", None
            ) or getattr(self, best_model_name, None)

            self.logger.info(
                f"Best model: {best_model_name} (score: {results[best_model_name]:.4f})"
            )

        self.scores = results
        return results

    def predict(self, X: np.ndarray, use_best: bool = True) -> np.ndarray:
        """
        Make predictions using ensemble models.

        Args:
            X: Feature matrix
            use_best: Use best performing model if True, otherwise use voting

        Returns:
            Predictions
        """
        if use_best and self.best_model is not None:
            return self.best_model.predict(X)
        elif self.voting_classifier is not None:
            return self.voting_classifier.predict(X)
        else:
            raise ValueError("No trained models available")

    def predict_proba(self, X: np.ndarray, use_best: bool = True) -> np.ndarray:
        """
        Get prediction probabilities.

        Args:
            X: Feature matrix
            use_best: Use best performing model if True, otherwise use voting

        Returns:
            Prediction probabilities
        """
        if use_best and self.best_model is not None:
            if hasattr(self.best_model, "predict_proba"):
                return self.best_model.predict_proba(X)
            else:
                # Convert predictions to probabilities
                preds = self.best_model.predict(X)
                proba = np.zeros((len(preds), 2))
                proba[np.arange(len(preds)), preds.astype(int)] = 1.0
                return proba
        elif self.voting_classifier is not None:
            return self.voting_classifier.predict_proba(X)
        else:
            raise ValueError("No trained models available")

    def evaluate(
        self, X_test: np.ndarray, y_test: np.ndarray
    ) -> Dict[str, Dict[str, Any]]:
        """
        Evaluate all ensemble models on test data.

        Args:
            X_test: Test feature matrix
            y_test: Test labels

        Returns:
            Evaluation results for each model
        """
        results = {}

        models = [
            ("voting", self.voting_classifier),
            ("bagging", self.bagging_classifier),
            ("gradient_boosting", self.gradient_boosting),
        ]

        for name, model in models:
            if model is not None:
                try:
                    predictions = model.predict(X_test)
                    accuracy = accuracy_score(y_test, predictions)
                    report = classification_report(
                        y_test, predictions, output_dict=True
                    )

                    results[name] = {
                        "accuracy": accuracy,
                        "classification_report": report,
                    }

                    self.logger.info(f"{name} test accuracy: {accuracy:.4f}")

                except Exception as e:
                    self.logger.error(f"Evaluation failed for {name}: {e}")
                    results[name] = {"error": str(e)}

        return results

    def get_feature_importance(
        self, model_name: Optional[str] = None
    ) -> Optional[np.ndarray]:
        """
        Get feature importance from ensemble models.

        Args:
            model_name: Specific model name, or None for best model

        Returns:
            Feature importance array
        """
        if model_name:
            model = getattr(self, f"{model_name}_classifier", None) or getattr(
                self, model_name, None
            )
        else:
            model = self.best_model

        if model is not None and hasattr(model, "feature_importances_"):
            return model.feature_importances_
        elif model is not None and hasattr(model, "estimators_"):
            # For voting classifier, average feature importance
            importances = []
            for estimator in model.estimators_:
                if hasattr(estimator, "feature_importances_"):
                    importances.append(estimator.feature_importances_)

            if importances:
                return np.mean(importances, axis=0)

        return None

    def get_model_info(self) -> Dict[str, Any]:
        """
        Get information about trained models.

        Returns:
            Model information dictionary
        """
        info = {
            "config": self.config,
            "scores": self.scores,
            "models_available": {},
            "best_model": None,
        }

        models = [
            ("voting", self.voting_classifier),
            ("bagging", self.bagging_classifier),
            ("gradient_boosting", self.gradient_boosting),
        ]

        for name, model in models:
            info["models_available"][name] = model is not None

        if self.best_model is not None:
            for name, model in models:
                if model is self.best_model:
                    info["best_model"] = name
                    break

        return info
