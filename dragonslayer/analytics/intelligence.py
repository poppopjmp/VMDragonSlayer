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
Threat Intelligence
===================

Threat intelligence analytics and processing.
Consolidates threat intelligence functionality from the enterprise reporting system.
"""

import hashlib
import json
import logging
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ThreatIndicator:
    """Threat indicator information."""

    indicator_type: str  # hash, ip, domain, url, etc.
    indicator_value: str
    threat_family: str
    confidence_score: float
    first_seen: datetime
    last_seen: datetime
    source: str
    tags: List[str] = None

    def __post_init__(self):
        if self.tags is None:
            self.tags = []


@dataclass
class ThreatIntelligence:
    """Comprehensive threat intelligence data."""

    threat_id: str
    threat_type: str
    threat_family: str
    severity: str
    first_seen: datetime
    last_seen: datetime
    sample_count: int
    affected_systems: List[str]
    indicators: List[ThreatIndicator]
    attribution: Optional[str] = None
    description: str = ""
    mitigation_recommendations: List[str] = None

    def __post_init__(self):
        if self.mitigation_recommendations is None:
            self.mitigation_recommendations = []


@dataclass
class ThreatCampaign:
    """Threat campaign tracking."""

    campaign_id: str
    campaign_name: str
    threat_actor: str
    start_date: datetime
    end_date: Optional[datetime]
    target_sectors: List[str]
    attack_vectors: List[str]
    associated_threats: List[str]
    campaign_description: str


class ThreatIntelligenceProcessor:
    """
    Threat intelligence processing and analysis engine.

    Consolidates threat intelligence functionality from enterprise components.
    """

    def __init__(self):
        self.threat_database: Dict[str, ThreatIntelligence] = {}
        self.indicator_cache: Dict[str, List[ThreatIndicator]] = defaultdict(list)
        self.campaign_tracking: Dict[str, ThreatCampaign] = {}
        self.family_statistics: Dict[str, Dict[str, Any]] = defaultdict(dict)

    def add_threat_intelligence(self, threat: ThreatIntelligence) -> bool:
        """Add new threat intelligence to the database."""
        try:
            self.threat_database[threat.threat_id] = threat

            # Index indicators
            for indicator in threat.indicators:
                self.indicator_cache[indicator.indicator_value].append(indicator)

            # Update family statistics
            self._update_family_statistics(threat)

            logger.info(f"Added threat intelligence: {threat.threat_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to add threat intelligence: {e}")
            return False

    def lookup_indicator(self, indicator_value: str) -> List[ThreatIndicator]:
        """Lookup threat indicators by value."""
        return self.indicator_cache.get(indicator_value, [])

    def get_threat_by_id(self, threat_id: str) -> Optional[ThreatIntelligence]:
        """Get threat intelligence by ID."""
        return self.threat_database.get(threat_id)

    def search_threats(
        self,
        family: Optional[str] = None,
        severity: Optional[str] = None,
        days_back: int = 30,
    ) -> List[ThreatIntelligence]:
        """Search threats with filters."""
        cutoff_date = datetime.now() - timedelta(days=days_back)
        results = []

        for threat in self.threat_database.values():
            # Apply filters
            if family and threat.threat_family.lower() != family.lower():
                continue

            if severity and threat.severity.lower() != severity.lower():
                continue

            if threat.last_seen < cutoff_date:
                continue

            results.append(threat)

        # Sort by last seen (most recent first)
        results.sort(key=lambda t: t.last_seen, reverse=True)
        return results

    def analyze_threat_trends(self, days: int = 30) -> Dict[str, Any]:
        """Analyze threat trends over time."""
        cutoff_date = datetime.now() - timedelta(days=days)
        recent_threats = [
            t for t in self.threat_database.values() if t.last_seen >= cutoff_date
        ]

        if not recent_threats:
            return self._get_empty_trends()

        # Family distribution
        family_counts = Counter(t.threat_family for t in recent_threats)

        # Severity distribution
        severity_counts = Counter(t.severity for t in recent_threats)

        # Daily threat counts
        daily_counts = defaultdict(int)
        for threat in recent_threats:
            date_key = threat.last_seen.strftime("%Y-%m-%d")
            daily_counts[date_key] += 1

        # Top threat families
        top_families = family_counts.most_common(10)

        # Calculate trend direction
        sorted_dates = sorted(daily_counts.keys())
        if len(sorted_dates) >= 7:
            recent_avg = sum(daily_counts[d] for d in sorted_dates[-7:]) / 7
            older_avg = sum(daily_counts[d] for d in sorted_dates[:-7]) / max(
                1, len(sorted_dates) - 7
            )

            if older_avg > 0:
                trend_percentage = ((recent_avg - older_avg) / older_avg) * 100
            else:
                trend_percentage = 0.0

            if trend_percentage > 10:
                trend_direction = "increasing"
            elif trend_percentage < -10:
                trend_direction = "decreasing"
            else:
                trend_direction = "stable"
        else:
            trend_direction = "insufficient_data"
            trend_percentage = 0.0

        return {
            "analysis_period": {
                "start_date": cutoff_date.isoformat(),
                "end_date": datetime.now().isoformat(),
                "days": days,
            },
            "threat_summary": {
                "total_threats": len(recent_threats),
                "unique_families": len(family_counts),
                "high_severity": len(
                    [t for t in recent_threats if t.severity.lower() == "high"]
                ),
                "medium_severity": len(
                    [t for t in recent_threats if t.severity.lower() == "medium"]
                ),
                "low_severity": len(
                    [t for t in recent_threats if t.severity.lower() == "low"]
                ),
            },
            "family_distribution": [
                {"family": family, "count": count} for family, count in top_families
            ],
            "severity_distribution": [
                {"severity": severity, "count": count}
                for severity, count in severity_counts.items()
            ],
            "daily_trends": [
                {"date": date, "count": count}
                for date, count in sorted(daily_counts.items())
            ],
            "trend_analysis": {
                "direction": trend_direction,
                "percentage_change": trend_percentage,
            },
        }

    def generate_threat_report(self, threat_id: str) -> Dict[str, Any]:
        """Generate detailed threat report."""
        threat = self.get_threat_by_id(threat_id)
        if not threat:
            return {"error": f"Threat {threat_id} not found"}

        # Analyze indicators
        indicator_analysis = self._analyze_indicators(threat.indicators)

        # Find related threats
        related_threats = self._find_related_threats(threat)

        # Generate timeline
        timeline = self._generate_threat_timeline(threat)

        return {
            "threat_id": threat.threat_id,
            "basic_info": {
                "threat_type": threat.threat_type,
                "threat_family": threat.threat_family,
                "severity": threat.severity,
                "description": threat.description,
            },
            "temporal_analysis": {
                "first_seen": threat.first_seen.isoformat(),
                "last_seen": threat.last_seen.isoformat(),
                "duration_days": (threat.last_seen - threat.first_seen).days,
                "sample_count": threat.sample_count,
            },
            "impact_analysis": {
                "affected_systems": threat.affected_systems,
                "system_count": len(threat.affected_systems),
            },
            "indicator_analysis": indicator_analysis,
            "related_threats": [
                {
                    "threat_id": rt.threat_id,
                    "threat_family": rt.threat_family,
                    "similarity_score": self._calculate_similarity(threat, rt),
                }
                for rt in related_threats
            ],
            "timeline": timeline,
            "mitigation": {
                "recommendations": threat.mitigation_recommendations,
                "attribution": threat.attribution,
            },
            "generated_at": datetime.now().isoformat(),
        }

    def detect_threat_campaigns(self) -> List[ThreatCampaign]:
        """Detect potential threat campaigns from patterns."""
        campaigns = []

        # Group threats by family and time proximity
        family_groups = defaultdict(list)
        for threat in self.threat_database.values():
            family_groups[threat.threat_family].append(threat)

        for family, threats in family_groups.items():
            if len(threats) < 3:  # Need at least 3 threats for a campaign
                continue

            # Sort by first seen
            threats.sort(key=lambda t: t.first_seen)

            # Look for clusters in time
            campaign_threats = []
            campaign_start = None

            for _i, threat in enumerate(threats):
                if not campaign_start:
                    campaign_start = threat.first_seen
                    campaign_threats = [threat]
                    continue

                # If this threat is within 30 days of the campaign start, add it
                if (threat.first_seen - campaign_start).days <= 30:
                    campaign_threats.append(threat)
                else:
                    # End current campaign if it has enough threats
                    if len(campaign_threats) >= 3:
                        campaign = self._create_campaign_from_threats(
                            family, campaign_threats
                        )
                        campaigns.append(campaign)

                    # Start new campaign
                    campaign_start = threat.first_seen
                    campaign_threats = [threat]

            # Check final campaign
            if len(campaign_threats) >= 3:
                campaign = self._create_campaign_from_threats(family, campaign_threats)
                campaigns.append(campaign)

        return campaigns

    def _update_family_statistics(self, threat: ThreatIntelligence):
        """Update family statistics with new threat."""
        family = threat.threat_family

        if family not in self.family_statistics:
            self.family_statistics[family] = {
                "total_count": 0,
                "first_seen": threat.first_seen,
                "last_seen": threat.last_seen,
                "severity_distribution": defaultdict(int),
                "sample_count": 0,
            }

        stats = self.family_statistics[family]
        stats["total_count"] += 1
        stats["sample_count"] += threat.sample_count
        stats["severity_distribution"][threat.severity] += 1

        # Update timestamps
        if threat.first_seen < stats["first_seen"]:
            stats["first_seen"] = threat.first_seen
        if threat.last_seen > stats["last_seen"]:
            stats["last_seen"] = threat.last_seen

    def _analyze_indicators(self, indicators: List[ThreatIndicator]) -> Dict[str, Any]:
        """Analyze threat indicators."""
        if not indicators:
            return {
                "total": 0,
                "types": {},
                "confidence": {"avg": 0, "min": 0, "max": 0},
            }

        indicator_types = Counter(ind.indicator_type for ind in indicators)
        confidence_scores = [ind.confidence_score for ind in indicators]

        return {
            "total": len(indicators),
            "types": dict(indicator_types),
            "confidence": {
                "avg": sum(confidence_scores) / len(confidence_scores),
                "min": min(confidence_scores),
                "max": max(confidence_scores),
            },
            "sources": list({ind.source for ind in indicators}),
        }

    def _find_related_threats(
        self, threat: ThreatIntelligence, limit: int = 5
    ) -> List[ThreatIntelligence]:
        """Find threats related to the given threat."""
        related = []

        for other_threat in self.threat_database.values():
            if other_threat.threat_id == threat.threat_id:
                continue

            similarity = self._calculate_similarity(threat, other_threat)
            if similarity > 0.3:  # Threshold for relatedness
                related.append(other_threat)

        # Sort by similarity and return top results
        related.sort(key=lambda t: self._calculate_similarity(threat, t), reverse=True)
        return related[:limit]

    def _calculate_similarity(
        self, threat1: ThreatIntelligence, threat2: ThreatIntelligence
    ) -> float:
        """Calculate similarity score between two threats."""
        similarity = 0.0

        # Family similarity
        if threat1.threat_family == threat2.threat_family:
            similarity += 0.4

        # Type similarity
        if threat1.threat_type == threat2.threat_type:
            similarity += 0.2

        # Time proximity (within 30 days)
        time_diff = abs((threat1.last_seen - threat2.last_seen).days)
        if time_diff <= 30:
            similarity += 0.2 * (1 - time_diff / 30)

        # Indicator overlap
        indicators1 = {ind.indicator_value for ind in threat1.indicators}
        indicators2 = {ind.indicator_value for ind in threat2.indicators}

        if indicators1 and indicators2:
            overlap = len(indicators1.intersection(indicators2))
            total = len(indicators1.union(indicators2))
            indicator_similarity = overlap / total if total > 0 else 0
            similarity += 0.2 * indicator_similarity

        return min(similarity, 1.0)

    def _generate_threat_timeline(
        self, threat: ThreatIntelligence
    ) -> List[Dict[str, Any]]:
        """Generate timeline for threat."""
        timeline = [
            {
                "date": threat.first_seen.isoformat(),
                "event": "First Detection",
                "description": f"Threat {threat.threat_id} first detected",
            }
        ]

        if threat.last_seen != threat.first_seen:
            timeline.append(
                {
                    "date": threat.last_seen.isoformat(),
                    "event": "Last Activity",
                    "description": "Most recent activity observed",
                }
            )

        return timeline

    def _create_campaign_from_threats(
        self, family: str, threats: List[ThreatIntelligence]
    ) -> ThreatCampaign:
        """Create a threat campaign from grouped threats."""
        # Use SHA256 for ID generation (avoid insecure md5)
        campaign_id = hashlib.sha256(
            f"{family}_{threats[0].first_seen}".encode()
        ).hexdigest()[:12]

        start_date = min(t.first_seen for t in threats)
        end_date = max(t.last_seen for t in threats)

        # Determine target sectors (simplified)
        all_systems = []
        for threat in threats:
            all_systems.extend(threat.affected_systems)

        target_sectors = ["Enterprise", "Healthcare", "Finance"]  # Simplified

        return ThreatCampaign(
            campaign_id=campaign_id,
            campaign_name=f"{family} Campaign {start_date.strftime('%Y-%m')}",
            threat_actor="Unknown",
            start_date=start_date,
            end_date=end_date,
            target_sectors=target_sectors,
            attack_vectors=["Email", "Web", "Network"],  # Simplified
            associated_threats=[t.threat_id for t in threats],
            campaign_description=f"Campaign involving {len(threats)} {family} threats",
        )

    def _get_empty_trends(self) -> Dict[str, Any]:
        """Return empty trends structure."""
        return {
            "analysis_period": {"start_date": "", "end_date": "", "days": 0},
            "threat_summary": {"total_threats": 0, "unique_families": 0},
            "family_distribution": [],
            "severity_distribution": [],
            "daily_trends": [],
            "trend_analysis": {"direction": "no_data", "percentage_change": 0.0},
        }

    def get_intelligence_statistics(self) -> Dict[str, Any]:
        """Get overall intelligence statistics."""
        total_threats = len(self.threat_database)
        total_indicators = sum(len(t.indicators) for t in self.threat_database.values())

        if total_threats == 0:
            return {
                "total_threats": 0,
                "total_indicators": 0,
                "family_count": 0,
                "average_indicators_per_threat": 0,
            }

        return {
            "total_threats": total_threats,
            "total_indicators": total_indicators,
            "family_count": len(self.family_statistics),
            "average_indicators_per_threat": total_indicators / total_threats,
            "family_statistics": dict(self.family_statistics),
            "cache_size": len(self.indicator_cache),
            "last_updated": datetime.now().isoformat(),
        }

    def export_intelligence(self, filepath: str):
        """Export threat intelligence to JSON file."""
        export_data = {
            "threats": {
                threat_id: asdict(threat)
                for threat_id, threat in self.threat_database.items()
            },
            "campaigns": {
                campaign_id: asdict(campaign)
                for campaign_id, campaign in self.campaign_tracking.items()
            },
            "statistics": self.get_intelligence_statistics(),
            "exported_at": datetime.now().isoformat(),
        }

        with open(filepath, "w") as f:
            json.dump(export_data, f, indent=2, default=str)

        logger.info(f"Threat intelligence exported to {filepath}")


# Convenience functions
def create_threat_indicator(
    indicator_type: str,
    value: str,
    family: str,
    confidence: float,
    source: str = "manual",
) -> ThreatIndicator:
    """Create a new threat indicator."""
    return ThreatIndicator(
        indicator_type=indicator_type,
        indicator_value=value,
        threat_family=family,
        confidence_score=confidence,
        first_seen=datetime.now(),
        last_seen=datetime.now(),
        source=source,
    )


def create_threat_intelligence(
    threat_type: str,
    family: str,
    severity: str,
    indicators: List[ThreatIndicator],
    description: str = "",
) -> ThreatIntelligence:
    """Create new threat intelligence entry."""
    # Use SHA256 for ID generation (avoid insecure md5)
    threat_id = hashlib.sha256(
        f"{family}_{threat_type}_{datetime.now()}".encode()
    ).hexdigest()[:12]

    return ThreatIntelligence(
        threat_id=threat_id,
        threat_type=threat_type,
        threat_family=family,
        severity=severity,
        first_seen=datetime.now(),
        last_seen=datetime.now(),
        sample_count=1,
        affected_systems=[],
        indicators=indicators,
        description=description,
    )
