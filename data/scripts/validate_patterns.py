#!/usr/bin/env python3
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
Pattern Database Validation Script
=================================

Validates pattern database integrity, schema compliance, and pattern quality.
"""

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Dict, List, Any, Tuple

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class PatternValidator:
    """Validates VM detection patterns for quality and correctness"""
    
    def __init__(self, schema_path: str = None):
        self.schema_path = schema_path
        self.schema = self._load_schema() if schema_path else None
        self.validation_errors = []
        self.validation_warnings = []
        
    def _load_schema(self) -> Dict[str, Any]:
        """Load JSON schema for pattern validation"""
        try:
            with open(self.schema_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load schema {self.schema_path}: {e}")
            return {}
    
    def validate_pattern_database(self, patterns_path: str) -> Tuple[bool, List[str], List[str]]:
        """Validate entire pattern database"""
        logger.info(f"Validating pattern database: {patterns_path}")
        
        self.validation_errors = []
        self.validation_warnings = []
        
        try:
            with open(patterns_path, 'r') as f:
                patterns_data = json.load(f)
        except Exception as e:
            self.validation_errors.append(f"Failed to load patterns file: {e}")
            return False, self.validation_errors, self.validation_warnings
        
        # Schema validation
        if self.schema:
            self._validate_schema(patterns_data)
        
        # Pattern-specific validation
        self._validate_patterns_structure(patterns_data)
        self._validate_pattern_quality(patterns_data)
        self._validate_pattern_coverage(patterns_data)
        
        is_valid = len(self.validation_errors) == 0
        
        logger.info(f"Validation completed: {len(self.validation_errors)} errors, {len(self.validation_warnings)} warnings")
        
        return is_valid, self.validation_errors, self.validation_warnings
    
    def _validate_schema(self, patterns_data: Dict[str, Any]):
        """Validate against JSON schema"""
        try:
            import jsonschema
            jsonschema.validate(patterns_data, self.schema)
            logger.info("Schema validation passed")
        except ImportError:
            self.validation_warnings.append("jsonschema not available - skipping schema validation")
        except jsonschema.ValidationError as e:
            self.validation_errors.append(f"Schema validation failed: {e.message}")
        except Exception as e:
            self.validation_errors.append(f"Schema validation error: {e}")
    
    def _validate_patterns_structure(self, patterns_data: Dict[str, Any]):
        """Validate basic pattern structure"""
        required_fields = ['version', 'patterns', 'metadata']
        
        for field in required_fields:
            if field not in patterns_data:
                self.validation_errors.append(f"Missing required field: {field}")
        
        # Validate patterns array
        patterns = patterns_data.get('patterns', [])
        if not isinstance(patterns, list):
            self.validation_errors.append("'patterns' field must be an array")
            return
        
        if len(patterns) == 0:
            self.validation_warnings.append("No patterns found in database")
            return
        
        # Validate individual patterns
        for i, pattern in enumerate(patterns):
            self._validate_single_pattern(pattern, i)
    
    def _validate_single_pattern(self, pattern: Dict[str, Any], index: int):
        """Validate a single pattern entry"""
        required_fields = ['id', 'name', 'type', 'category', 'signature', 'confidence']
        
        for field in required_fields:
            if field not in pattern:
                self.validation_errors.append(f"Pattern {index}: missing required field '{field}'")
        
        # Validate pattern ID uniqueness (will be checked at database level)
        pattern_id = pattern.get('id')
        if pattern_id and not isinstance(pattern_id, str):
            self.validation_errors.append(f"Pattern {index}: 'id' must be a string")
        
        # Validate signature
        signature = pattern.get('signature')
        if signature:
            self._validate_pattern_signature(signature, index)
        
        # Validate confidence score
        confidence = pattern.get('confidence')
        if confidence is not None:
            if not isinstance(confidence, (int, float)) or not (0 <= confidence <= 100):
                self.validation_errors.append(f"Pattern {index}: confidence must be a number between 0 and 100")
        
        # Validate category
        category = pattern.get('category')
        valid_categories = ['vm_detection', 'packer_detection', 'obfuscation', 'anti_debug', 'anti_vm']
        if category and category not in valid_categories:
            self.validation_warnings.append(f"Pattern {index}: unknown category '{category}'")
        
        # Validate type
        pattern_type = pattern.get('type')
        valid_types = ['bytes', 'regex', 'yara', 'opcode', 'structural']
        if pattern_type and pattern_type not in valid_types:
            self.validation_warnings.append(f"Pattern {index}: unknown type '{pattern_type}'")
    
    def _validate_pattern_signature(self, signature: Dict[str, Any], pattern_index: int):
        """Validate pattern signature"""
        signature_type = signature.get('type', '')
        
        if signature_type == 'bytes':
            self._validate_bytes_signature(signature, pattern_index)
        elif signature_type == 'regex':
            self._validate_regex_signature(signature, pattern_index)
        elif signature_type == 'yara':
            self._validate_yara_signature(signature, pattern_index)
        elif signature_type == 'opcode':
            self._validate_opcode_signature(signature, pattern_index)
        else:
            self.validation_warnings.append(f"Pattern {pattern_index}: unknown signature type '{signature_type}'")
    
    def _validate_bytes_signature(self, signature: Dict[str, Any], pattern_index: int):
        """Validate byte pattern signature"""
        pattern = signature.get('pattern', '')
        
        if not pattern:
            self.validation_errors.append(f"Pattern {pattern_index}: bytes signature missing 'pattern'")
            return
        
        # Basic hex validation
        try:
            # Remove wildcards and spaces
            clean_pattern = pattern.replace('?', '0').replace(' ', '')
            if clean_pattern:
                bytes.fromhex(clean_pattern)
        except ValueError:
            self.validation_errors.append(f"Pattern {pattern_index}: invalid hex pattern")
        
        # Check minimum pattern length
        effective_bytes = pattern.replace('?', '').replace(' ', '')
        if len(effective_bytes) < 6:  # At least 3 bytes
            self.validation_warnings.append(f"Pattern {pattern_index}: pattern may be too short for reliable detection")
    
    def _validate_regex_signature(self, signature: Dict[str, Any], pattern_index: int):
        """Validate regex pattern signature"""
        import re
        
        pattern = signature.get('pattern', '')
        
        if not pattern:
            self.validation_errors.append(f"Pattern {pattern_index}: regex signature missing 'pattern'")
            return
        
        try:
            re.compile(pattern)
        except re.error as e:
            self.validation_errors.append(f"Pattern {pattern_index}: invalid regex pattern - {e}")
    
    def _validate_yara_signature(self, signature: Dict[str, Any], pattern_index: int):
        """Validate YARA rule signature"""
        rule = signature.get('rule', '')
        
        if not rule:
            self.validation_errors.append(f"Pattern {pattern_index}: YARA signature missing 'rule'")
            return
        
        # Basic YARA syntax validation
        required_sections = ['rule ', '{', '}']
        for section in required_sections:
            if section not in rule:
                self.validation_errors.append(f"Pattern {pattern_index}: YARA rule missing '{section}'")
        
        # Check for condition section
        if 'condition:' not in rule:
            self.validation_warnings.append(f"Pattern {pattern_index}: YARA rule should have a condition section")
    
    def _validate_opcode_signature(self, signature: Dict[str, Any], pattern_index: int):
        """Validate opcode pattern signature"""
        opcodes = signature.get('opcodes', [])
        
        if not opcodes:
            self.validation_errors.append(f"Pattern {pattern_index}: opcode signature missing 'opcodes'")
            return
        
        if not isinstance(opcodes, list):
            self.validation_errors.append(f"Pattern {pattern_index}: 'opcodes' must be an array")
            return
        
        # Validate individual opcodes
        valid_x86_opcodes = {
            'mov', 'push', 'pop', 'call', 'ret', 'jmp', 'je', 'jne', 'jz', 'jnz',
            'add', 'sub', 'mul', 'div', 'xor', 'and', 'or', 'not', 'cmp', 'test',
            'int', 'nop', 'lea', 'inc', 'dec'
        }
        
        for opcode in opcodes:
            if isinstance(opcode, str):
                base_opcode = opcode.split()[0].lower()
                if base_opcode not in valid_x86_opcodes:
                    self.validation_warnings.append(f"Pattern {pattern_index}: unknown opcode '{base_opcode}'")
    
    def _validate_pattern_quality(self, patterns_data: Dict[str, Any]):
        """Validate pattern quality and effectiveness"""
        patterns = patterns_data.get('patterns', [])
        
        # Check for duplicate patterns
        pattern_ids = []
        signatures = []
        
        for i, pattern in enumerate(patterns):
            pattern_id = pattern.get('id')
            if pattern_id in pattern_ids:
                self.validation_errors.append(f"Duplicate pattern ID: {pattern_id}")
            else:
                pattern_ids.append(pattern_id)
            
            # Check for duplicate signatures (simplified)
            signature = pattern.get('signature', {})
            sig_str = json.dumps(signature, sort_keys=True)
            if sig_str in signatures:
                self.validation_warnings.append(f"Pattern {i}: potential duplicate signature")
            else:
                signatures.append(sig_str)
        
        # Check confidence score distribution
        confidences = [p.get('confidence', 0) for p in patterns]
        if confidences:
            avg_confidence = sum(confidences) / len(confidences)
            if avg_confidence < 70:
                self.validation_warnings.append(f"Low average confidence score: {avg_confidence:.1f}")
            
            high_confidence_count = sum(1 for c in confidences if c >= 90)
            if high_confidence_count / len(confidences) < 0.3:
                self.validation_warnings.append("Less than 30% of patterns have high confidence (≥90)")
    
    def _validate_pattern_coverage(self, patterns_data: Dict[str, Any]):
        """Validate pattern coverage across different VM types and techniques"""
        patterns = patterns_data.get('patterns', [])
        
        # Check category coverage
        categories = [p.get('category') for p in patterns]
        category_counts = {}
        for cat in categories:
            if cat:
                category_counts[cat] = category_counts.get(cat, 0) + 1
        
        required_categories = ['vm_detection', 'packer_detection', 'obfuscation']
        for req_cat in required_categories:
            if req_cat not in category_counts:
                self.validation_warnings.append(f"No patterns found for category: {req_cat}")
            elif category_counts[req_cat] < 5:
                self.validation_warnings.append(f"Low pattern count for category '{req_cat}': {category_counts[req_cat]}")
        
        # Check type coverage
        types = [p.get('type') for p in patterns]
        type_counts = {}
        for typ in types:
            if typ:
                type_counts[typ] = type_counts.get(typ, 0) + 1
        
        if 'bytes' not in type_counts or type_counts['bytes'] < 10:
            self.validation_warnings.append("Insufficient byte patterns for robust detection")
        
        logger.info(f"Pattern coverage - Categories: {category_counts}, Types: {type_counts}")


def create_default_schema() -> Dict[str, Any]:
    """Create default JSON schema for pattern database"""
    return {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "required": ["version", "patterns", "metadata"],
        "properties": {
            "version": {
                "type": "string",
                "pattern": "^\\d+\\.\\d+\\.\\d+$"
            },
            "patterns": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["id", "name", "type", "category", "signature", "confidence"],
                    "properties": {
                        "id": {
                            "type": "string",
                            "minLength": 1
                        },
                        "name": {
                            "type": "string",
                            "minLength": 1
                        },
                        "type": {
                            "type": "string",
                            "enum": ["bytes", "regex", "yara", "opcode", "structural"]
                        },
                        "category": {
                            "type": "string",
                            "enum": ["vm_detection", "packer_detection", "obfuscation", "anti_debug", "anti_vm"]
                        },
                        "signature": {
                            "type": "object",
                            "required": ["type"],
                            "properties": {
                                "type": {
                                    "type": "string"
                                }
                            }
                        },
                        "confidence": {
                            "type": "number",
                            "minimum": 0,
                            "maximum": 100
                        },
                        "description": {
                            "type": "string"
                        },
                        "references": {
                            "type": "array",
                            "items": {
                                "type": "string"
                            }
                        },
                        "tags": {
                            "type": "array",
                            "items": {
                                "type": "string"
                            }
                        }
                    }
                }
            },
            "metadata": {
                "type": "object",
                "required": ["created", "version"],
                "properties": {
                    "created": {
                        "type": "string",
                        "format": "date-time"
                    },
                    "version": {
                        "type": "string"
                    },
                    "author": {
                        "type": "string"
                    },
                    "description": {
                        "type": "string"
                    }
                }
            }
        }
    }


def main():
    """Main validation execution"""
    parser = argparse.ArgumentParser(description="Validate VMDragonSlayer pattern database")
    parser.add_argument('patterns', help='Path to patterns database JSON file')
    parser.add_argument('--schema', '-s', help='Path to JSON schema file')
    parser.add_argument('--create-schema', action='store_true',
                       help='Create default schema file')
    parser.add_argument('--output-schema', default='pattern_database_schema.json',
                       help='Output path for created schema')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Create default schema if requested
    if args.create_schema:
        schema = create_default_schema()
        with open(args.output_schema, 'w') as f:
            json.dump(schema, f, indent=2)
        logger.info(f"Created default schema: {args.output_schema}")
        return
    
    # Validate patterns
    try:
        validator = PatternValidator(args.schema)
        is_valid, errors, warnings = validator.validate_pattern_database(args.patterns)
        
        # Print results
        if errors:
            print("\nValidation Errors:")
            for error in errors:
                print(f"   {error}")
        
        if warnings:
            print("\nValidation Warnings:")
            for warning in warnings:
                print(f"  ⚠️  {warning}")
        
        if is_valid:
            print(f"\n Pattern database validation passed with {len(warnings)} warnings")
            return 0
        else:
            print(f"\n Pattern database validation failed with {len(errors)} errors")
            return 1
            
    except Exception as e:
        logger.error(f"Validation failed: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
