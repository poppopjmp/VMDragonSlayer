"""
Pattern Recognizer Module

Performs pattern matching against instruction sequences to identify
VM handlers and obfuscation patterns.

Moving completely to YARA rules for pattern definitions and matching will be more efficient and flexible.
"""

import logging
import re
from dataclasses import dataclass
from typing import List, Optional, Tuple, Dict, Any

from .database import Pattern, PatternDatabase

logger = logging.getLogger(__name__)


@dataclass
class Match:
    """
    Represents a pattern match result.
    
    """
    pattern: Pattern
    start_offset: int
    end_offset: int
    confidence: float
    matched_bytes: str
    context: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.context is None:
            self.context = {}


class PatternRecognizer:
    """
    Recognizes VM handler patterns in instruction sequences.

    """
    
    def __init__(self, database: PatternDatabase):
        """
        Initialize pattern recognizer.

        """
        self.database = database
        self._compiled_patterns: Dict[str, re.Pattern] = {}
    
    def recognize(self, 
                  instruction_bytes: str,
                  min_confidence: float = 0.7,
                  architecture: Optional[str] = None,
                  handler_type: Optional[str] = None) -> List[Match]:
        """
        Recognize patterns in instruction byte sequence.

        """
        # Convert enum to string if needed
        if architecture and hasattr(architecture, 'value'):
            architecture = architecture.value
        if handler_type and hasattr(handler_type, 'value'):
            handler_type = handler_type.value
        
        # Search for relevant patterns
        patterns = self.database.search(
            architecture=architecture,
            handler_type=handler_type,
            min_confidence=min_confidence * 0.8 
        )
        
        if not patterns:
            logger.debug("No patterns found matching search criteria")
            return []
        
        # Normalize input bytes
        normalized_bytes = self._normalize_bytes(instruction_bytes)
        
        # Find matches
        matches = []
        for pattern in patterns:
            pattern_matches = self._match_pattern(pattern, normalized_bytes)
            for match in pattern_matches:
                if match.confidence >= min_confidence:
                    matches.append(match)
        
        matches.sort(key=lambda m: m.confidence, reverse=True)
        
        logger.info(f"Found {len(matches)} matches (min_confidence={min_confidence})")
        return matches
    
    def recognize_single(self,
                        instruction_bytes: str,
                        min_confidence: float = 0.7,
                        architecture: Optional[str] = None,
                        handler_type: Optional[str] = None) -> Optional[Match]:
        """
        Recognize the best matching pattern.

        """
        matches = self.recognize(
            instruction_bytes,
            min_confidence=min_confidence,
            architecture=architecture,
            handler_type=handler_type
        )
        return matches[0] if matches else None
    
    def _match_pattern(self, pattern: Pattern, normalized_bytes: str) -> List[Match]:
        """
        Match a single pattern against byte sequence.

        """
        matches = []
        
        # Try main signature
        match = self._try_match(pattern, pattern.signature, normalized_bytes, 0)
        if match:
            matches.append(match)
        
        # Try variants
        for i, variant in enumerate(pattern.variants):
            match = self._try_match(pattern, variant, normalized_bytes, i + 1)
            if match:
                matches.append(match)
        
        return matches
    
    def _try_match(self, 
                   pattern: Pattern, 
                   signature: str, 
                   normalized_bytes: str,
                   variant_index: int) -> Optional[Match]:
        """
        Try matching a specific signature.

        """
        # Normalize signature
        sig_normalized = self._normalize_bytes(signature)
        
        # Convert to regex pattern if wildcards present
        if pattern.wildcards or '?' in sig_normalized:
            regex_pattern = self._signature_to_regex(sig_normalized)
            return self._regex_match(pattern, regex_pattern, normalized_bytes, variant_index)
        else:
            # Exact match
            return self._exact_match(pattern, sig_normalized, normalized_bytes, variant_index)
    
    def _exact_match(self,
                     pattern: Pattern,
                     signature: str,
                     normalized_bytes: str,
                     variant_index: int) -> Optional[Match]:
        """
        Perform exact byte matching.

        """
        # Find all occurrences
        index = normalized_bytes.find(signature)
        if index == -1:
            return None

        confidence = pattern.confidence
        
        if variant_index > 0:
            confidence *= 0.95 
        
        matched_bytes = normalized_bytes[index:index + len(signature)]
        
        return Match(
            pattern=pattern,
            start_offset=index // 2,  # Convert to byte offset
            end_offset=(index + len(signature)) // 2,
            confidence=confidence,
            matched_bytes=self._format_bytes(matched_bytes),
            context={'variant_index': variant_index, 'match_type': 'exact'}
        )
    
    def _regex_match(self,
                     pattern: Pattern,
                     regex_pattern: str,
                     normalized_bytes: str,
                     variant_index: int) -> Optional[Match]:
        """
        Perform regex-based matching with wildcards.

        """
        # Compile and cache regex
        if regex_pattern not in self._compiled_patterns:
            self._compiled_patterns[regex_pattern] = re.compile(regex_pattern)
        
        compiled = self._compiled_patterns[regex_pattern]
        match = compiled.search(normalized_bytes)
        
        if not match:
            return None
        
        matched_str = match.group(0)
        wildcard_count = regex_pattern.count('.{2}') 
        total_bytes = len(matched_str) // 2
        exact_bytes = total_bytes - wildcard_count
        
        # Base confidence from pattern
        confidence = pattern.confidence
        
        # Adjust for wildcard ratio (more exact bytes = higher confidence)
        if total_bytes > 0:
            exactness_ratio = exact_bytes / total_bytes
            confidence *= (0.7 + 0.3 * exactness_ratio)  
        # Apply variant penalty
        if variant_index > 0:
            confidence *= 0.95
        
        return Match(
            pattern=pattern,
            start_offset=match.start() // 2,
            end_offset=match.end() // 2,
            confidence=confidence,
            matched_bytes=self._format_bytes(matched_str),
            context={
                'variant_index': variant_index,
                'match_type': 'wildcard',
                'wildcard_count': wildcard_count,
                'exactness_ratio': exactness_ratio
            }
        )
    
    def _signature_to_regex(self, signature: str) -> str:
        """
        Convert signature with wildcards to regex pattern.

        """
        # Replace ?? with regex wildcard for any two hex chars
        regex = signature.replace('??', '.{2}')
        return regex
    
    def _normalize_bytes(self, byte_string: str) -> str:
        """
        Normalize byte string by removing spaces, pipes, and converting to uppercase.

        """
        # Remove common separators
        normalized = byte_string.replace(' ', '').replace('|', '').replace(',', '')
        normalized = normalized.replace('\n', '').replace('\t', '')
        return normalized.upper()
    
    def _format_bytes(self, byte_string: str) -> str:
        """
        Format byte string with spaces for readability.

        """
        return ' '.join(byte_string[i:i+2] for i in range(0, len(byte_string), 2))
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get recognizer statistics.

        """
        return {
            'total_patterns': len(self.database),
            'compiled_patterns': len(self._compiled_patterns),
            'database_stats': self.database.get_statistics()
        }


class SequenceRecognizer:
    """
    Recognizes patterns across instruction sequences (multi-instruction patterns).
    
    """
    
    def __init__(self, database: PatternDatabase):

        self.database = database
        self.recognizer = PatternRecognizer(database)
    
    def recognize_sequence(self,
                          instructions: List[str],
                          window_size: int = 5,
                          min_confidence: float = 0.7,
                          architecture: Optional[str] = None) -> List[Match]:
        """
        Recognize patterns across a sequence of instructions.

        """
        all_matches = []
        
        # Sliding window over instructions
        for i in range(len(instructions) - window_size + 1):
            window = instructions[i:i + window_size]
            combined_bytes = ' '.join(window)
            
            # Recognize in this window
            matches = self.recognizer.recognize(
                combined_bytes,
                min_confidence=min_confidence,
                architecture=architecture
            )
            
            # Adjust offsets to account for position in sequence
            for match in matches:
                match.start_offset += i
                match.end_offset += i
                match.context['window_start'] = i
                match.context['window_size'] = window_size
            
            all_matches.extend(matches)
        
        # Remove duplicate matches (same pattern, overlapping ranges)
        unique_matches = self._deduplicate_matches(all_matches)
        
        return unique_matches
    
    def _deduplicate_matches(self, matches: List[Match]) -> List[Match]:
        """
        Remove duplicate/overlapping matches, keeping highest confidence.

        """
        if not matches:
            return []
        
        # Sort by confidence (highest first)
        matches.sort(key=lambda m: m.confidence, reverse=True)
        
        unique = []
        used_ranges = []
        
        for match in matches:
            match_range = (match.start_offset, match.end_offset)
            
            # Check if this range overlaps with any used range
            overlaps = False
            for used_range in used_ranges:
                if self._ranges_overlap(match_range, used_range):
                    overlaps = True
                    break
            
            if not overlaps:
                unique.append(match)
                used_ranges.append(match_range)
        
        return unique
    
    def _ranges_overlap(self, range1: Tuple[int, int], range2: Tuple[int, int]) -> bool:
        """
        Check if two ranges overlap.
        
        """
        return not (range1[1] <= range2[0] or range2[1] <= range1[0])
