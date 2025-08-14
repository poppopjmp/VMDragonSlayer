"""
VM Discovery Database Manager
============================

Database management for VM detection results, patterns, and metadata.
Provides persistent storage and retrieval of analysis results.
"""

import sqlite3
import json
import logging
import hashlib
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from datetime import datetime

from ...core.exceptions import DataError, InvalidDataError

logger = logging.getLogger(__name__)


class VMDatabase:
    """
    Database manager for VM discovery results.
    
    Provides persistent storage for:
    - VM detection results
    - Handler patterns
    - Analysis metadata
    - Performance metrics
    """
    
    def __init__(self, database_path: str = "vm_discovery.db"):
        """
        Initialize VM database.
        
        Args:
            database_path: Path to SQLite database file
        """
        self.database_path = Path(database_path)
        self.logger = logging.getLogger(f"{__name__}.VMDatabase")
        
        # Ensure database directory exists
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize database
        self._initialize_database()
        
        self.logger.info(f"VM database initialized: {self.database_path}")
    
    def _initialize_database(self) -> None:
        """Initialize database schema"""
        try:
            with sqlite3.connect(self.database_path) as conn:
                cursor = conn.cursor()
                
                # VM analysis results table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS vm_analyses (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        sample_hash TEXT UNIQUE NOT NULL,
                        sample_size INTEGER NOT NULL,
                        vm_detected BOOLEAN NOT NULL,
                        vm_type TEXT,
                        confidence REAL NOT NULL,
                        handler_count INTEGER DEFAULT 0,
                        analysis_results TEXT,  -- JSON
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # VM handlers table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS vm_handlers (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        analysis_id INTEGER,
                        address TEXT NOT NULL,
                        name TEXT NOT NULL,
                        handler_type TEXT NOT NULL,
                        size INTEGER NOT NULL,
                        bytecode TEXT,  -- hex encoded
                        instructions TEXT,  -- JSON array
                        confidence REAL NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (analysis_id) REFERENCES vm_analyses (id)
                    )
                """)
                
                # Pattern database table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS vm_patterns (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        pattern_name TEXT NOT NULL,
                        pattern_type TEXT NOT NULL,
                        pattern_bytes TEXT NOT NULL,  -- hex encoded
                        description TEXT,
                        confidence REAL DEFAULT 0.5,
                        usage_count INTEGER DEFAULT 0,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Analysis metadata table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS analysis_metadata (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        analysis_id INTEGER,
                        key TEXT NOT NULL,
                        value TEXT,  -- JSON value
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (analysis_id) REFERENCES vm_analyses (id)
                    )
                """)
                
                # Create indexes for better performance
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_sample_hash ON vm_analyses (sample_hash)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_vm_detected ON vm_analyses (vm_detected)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_handler_type ON vm_handlers (handler_type)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_pattern_type ON vm_patterns (pattern_type)")
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to initialize database: {e}")
            raise DataError(
                "Failed to initialize VM database",
                error_code="DATABASE_INIT_FAILED",
                cause=e
            )
    
    def store_analysis_result(self, binary_data: bytes, analysis_result: Dict[str, Any]) -> int:
        """
        Store VM analysis result in database.
        
        Args:
            binary_data: Original binary data
            analysis_result: Analysis result dictionary
            
        Returns:
            Analysis ID
        """
        if not binary_data:
            raise InvalidDataError("Binary data cannot be empty")
        
        if not analysis_result:
            raise InvalidDataError("Analysis result cannot be empty")
        
        try:
            sample_hash = hashlib.sha256(binary_data).hexdigest()
            
            with sqlite3.connect(self.database_path) as conn:
                cursor = conn.cursor()
                
                # Insert main analysis record
                cursor.execute("""
                    INSERT OR REPLACE INTO vm_analyses 
                    (sample_hash, sample_size, vm_detected, vm_type, confidence, 
                     handler_count, analysis_results, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                """, (
                    sample_hash,
                    len(binary_data),
                    analysis_result.get('vm_detected', False),
                    analysis_result.get('vm_type', 'unknown'),
                    analysis_result.get('confidence', 0.0),
                    len(analysis_result.get('vm_structure', {}).get('handlers', [])) if analysis_result.get('vm_structure') else 0,
                    json.dumps(analysis_result)
                ))
                
                analysis_id = cursor.lastrowid
                
                # Store handlers if present
                vm_structure = analysis_result.get('vm_structure')
                if vm_structure and 'handlers' in vm_structure:
                    self._store_handlers(cursor, analysis_id, vm_structure['handlers'])
                
                # Store metadata
                metadata = analysis_result.get('analysis_summary', {})
                for key, value in metadata.items():
                    cursor.execute("""
                        INSERT INTO analysis_metadata (analysis_id, key, value)
                        VALUES (?, ?, ?)
                    """, (analysis_id, key, json.dumps(value)))
                
                conn.commit()
                
                self.logger.info(f"Stored analysis result with ID: {analysis_id}")
                return analysis_id
                
        except Exception as e:
            self.logger.error(f"Failed to store analysis result: {e}")
            raise DataError(
                "Failed to store analysis result",
                error_code="STORE_ANALYSIS_FAILED",
                cause=e
            )
    
    def _store_handlers(self, cursor: sqlite3.Cursor, analysis_id: int, 
                       handlers: List[Dict[str, Any]]) -> None:
        """Store handler information"""
        for handler in handlers:
            cursor.execute("""
                INSERT INTO vm_handlers 
                (analysis_id, address, name, handler_type, size, bytecode, 
                 instructions, confidence)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                analysis_id,
                str(handler.get('address', '')),
                handler.get('name', ''),
                handler.get('type', 'unknown'),
                handler.get('size', 0),
                handler.get('bytecode', ''),  # Assume already hex encoded
                json.dumps(handler.get('instructions', [])),
                handler.get('confidence', 0.0)
            ))
    
    def get_analysis_result(self, sample_hash: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve analysis result by sample hash.
        
        Args:
            sample_hash: SHA256 hash of the sample
            
        Returns:
            Analysis result dictionary or None if not found
        """
        try:
            with sqlite3.connect(self.database_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT analysis_results FROM vm_analyses 
                    WHERE sample_hash = ?
                """, (sample_hash,))
                
                result = cursor.fetchone()
                
                if result:
                    return json.loads(result[0])
                
                return None
                
        except Exception as e:
            self.logger.error(f"Failed to retrieve analysis result: {e}")
            raise DataError(
                "Failed to retrieve analysis result",
                error_code="GET_ANALYSIS_FAILED",
                cause=e
            )
    
    def find_similar_samples(self, confidence_threshold: float = 0.8, 
                           vm_type: Optional[str] = None,
                           handler_count_range: Optional[Tuple[int, int]] = None) -> List[Dict[str, Any]]:
        """
        Find similar VM samples based on criteria.
        
        Args:
            confidence_threshold: Minimum confidence threshold
            vm_type: Optional VM type filter
            handler_count_range: Optional (min, max) handler count range
            
        Returns:
            List of matching analysis records
        """
        try:
            with sqlite3.connect(self.database_path) as conn:
                cursor = conn.cursor()
                
                query = "SELECT * FROM vm_analyses WHERE confidence >= ?"
                params = [confidence_threshold]
                
                if vm_type:
                    query += " AND vm_type = ?"
                    params.append(vm_type)
                
                if handler_count_range:
                    min_count, max_count = handler_count_range
                    query += " AND handler_count BETWEEN ? AND ?"
                    params.extend([min_count, max_count])
                
                query += " ORDER BY confidence DESC"
                
                cursor.execute(query, params)
                rows = cursor.fetchall()
                
                # Convert to dictionaries
                columns = [desc[0] for desc in cursor.description]
                results = []
                
                for row in rows:
                    record = dict(zip(columns, row))
                    # Parse JSON fields
                    if record['analysis_results']:
                        record['analysis_results'] = json.loads(record['analysis_results'])
                    results.append(record)
                
                return results
                
        except Exception as e:
            self.logger.error(f"Failed to find similar samples: {e}")
            raise DataError(
                "Failed to find similar samples",
                error_code="FIND_SIMILAR_FAILED",
                cause=e
            )
    
    def store_pattern(self, pattern_name: str, pattern_type: str, 
                     pattern_bytes: bytes, description: str = "",
                     confidence: float = 0.5) -> int:
        """
        Store a VM pattern in the database.
        
        Args:
            pattern_name: Name of the pattern
            pattern_type: Type/category of the pattern
            pattern_bytes: Pattern byte sequence
            description: Optional description
            confidence: Pattern confidence (0.0 to 1.0)
            
        Returns:
            Pattern ID
        """
        try:
            with sqlite3.connect(self.database_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    INSERT OR REPLACE INTO vm_patterns 
                    (pattern_name, pattern_type, pattern_bytes, description, 
                     confidence, updated_at)
                    VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                """, (
                    pattern_name,
                    pattern_type,
                    pattern_bytes.hex(),
                    description,
                    confidence
                ))
                
                pattern_id = cursor.lastrowid
                conn.commit()
                
                self.logger.info(f"Stored pattern '{pattern_name}' with ID: {pattern_id}")
                return pattern_id
                
        except Exception as e:
            self.logger.error(f"Failed to store pattern: {e}")
            raise DataError(
                "Failed to store pattern",
                error_code="STORE_PATTERN_FAILED",
                cause=e
            )
    
    def get_patterns_by_type(self, pattern_type: str) -> List[Dict[str, Any]]:
        """
        Retrieve patterns by type.
        
        Args:
            pattern_type: Pattern type to retrieve
            
        Returns:
            List of pattern dictionaries
        """
        try:
            with sqlite3.connect(self.database_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT * FROM vm_patterns 
                    WHERE pattern_type = ? 
                    ORDER BY confidence DESC
                """, (pattern_type,))
                
                rows = cursor.fetchall()
                columns = [desc[0] for desc in cursor.description]
                
                patterns = []
                for row in rows:
                    pattern = dict(zip(columns, row))
                    # Convert hex string back to bytes
                    pattern['pattern_bytes'] = bytes.fromhex(pattern['pattern_bytes'])
                    patterns.append(pattern)
                
                return patterns
                
        except Exception as e:
            self.logger.error(f"Failed to get patterns by type: {e}")
            raise DataError(
                "Failed to get patterns by type",
                error_code="GET_PATTERNS_FAILED",
                cause=e
            )
    
    def update_pattern_usage(self, pattern_id: int) -> None:
        """
        Update pattern usage count.
        
        Args:
            pattern_id: Pattern ID to update
        """
        try:
            with sqlite3.connect(self.database_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    UPDATE vm_patterns 
                    SET usage_count = usage_count + 1,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                """, (pattern_id,))
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to update pattern usage: {e}")
            # Don't raise exception for usage count updates
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get database statistics.
        
        Returns:
            Statistics dictionary
        """
        try:
            with sqlite3.connect(self.database_path) as conn:
                cursor = conn.cursor()
                
                # Analysis statistics
                cursor.execute("SELECT COUNT(*) FROM vm_analyses")
                total_analyses = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(*) FROM vm_analyses WHERE vm_detected = 1")
                vm_detected_count = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(*) FROM vm_handlers")
                total_handlers = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(*) FROM vm_patterns")
                total_patterns = cursor.fetchone()[0]
                
                # VM type distribution
                cursor.execute("""
                    SELECT vm_type, COUNT(*) 
                    FROM vm_analyses 
                    WHERE vm_detected = 1 
                    GROUP BY vm_type
                """)
                vm_type_distribution = dict(cursor.fetchall())
                
                # Handler type distribution
                cursor.execute("""
                    SELECT handler_type, COUNT(*) 
                    FROM vm_handlers 
                    GROUP BY handler_type
                """)
                handler_type_distribution = dict(cursor.fetchall())
                
                return {
                    'total_analyses': total_analyses,
                    'vm_detected_count': vm_detected_count,
                    'vm_detection_rate': vm_detected_count / total_analyses if total_analyses > 0 else 0,
                    'total_handlers': total_handlers,
                    'total_patterns': total_patterns,
                    'vm_type_distribution': vm_type_distribution,
                    'handler_type_distribution': handler_type_distribution,
                    'database_size': self.database_path.stat().st_size if self.database_path.exists() else 0
                }
                
        except Exception as e:
            self.logger.error(f"Failed to get statistics: {e}")
            return {'error': str(e)}
    
    def cleanup_old_records(self, days_old: int = 30) -> int:
        """
        Clean up old analysis records.
        
        Args:
            days_old: Remove records older than this many days
            
        Returns:
            Number of records removed
        """
        try:
            with sqlite3.connect(self.database_path) as conn:
                cursor = conn.cursor()
                
                # Delete old analyses and their related records
                cursor.execute("""
                    DELETE FROM vm_analyses 
                    WHERE created_at < datetime('now', '-{} days')
                """.format(days_old))
                
                deleted_count = cursor.rowcount
                conn.commit()
                
                self.logger.info(f"Cleaned up {deleted_count} old records")
                return deleted_count
                
        except Exception as e:
            self.logger.error(f"Failed to cleanup old records: {e}")
            raise DataError(
                "Failed to cleanup old records",
                error_code="CLEANUP_FAILED",
                cause=e
            )
    
    def export_data(self, output_path: str, format: str = "json") -> None:
        """
        Export database data to file.
        
        Args:
            output_path: Output file path
            format: Export format ("json" or "csv")
        """
        try:
            with sqlite3.connect(self.database_path) as conn:
                if format.lower() == "json":
                    # Export as JSON
                    data = {
                        'analyses': [],
                        'handlers': [],
                        'patterns': []
                    }
                    
                    # Export analyses
                    cursor = conn.cursor()
                    cursor.execute("SELECT * FROM vm_analyses")
                    columns = [desc[0] for desc in cursor.description]
                    for row in cursor.fetchall():
                        record = dict(zip(columns, row))
                        if record['analysis_results']:
                            record['analysis_results'] = json.loads(record['analysis_results'])
                        data['analyses'].append(record)
                    
                    # Export handlers
                    cursor.execute("SELECT * FROM vm_handlers")
                    columns = [desc[0] for desc in cursor.description]
                    for row in cursor.fetchall():
                        record = dict(zip(columns, row))
                        if record['instructions']:
                            record['instructions'] = json.loads(record['instructions'])
                        data['handlers'].append(record)
                    
                    # Export patterns
                    cursor.execute("SELECT * FROM vm_patterns")
                    columns = [desc[0] for desc in cursor.description]
                    for row in cursor.fetchall():
                        data['patterns'].append(dict(zip(columns, row)))
                    
                    with open(output_path, 'w') as f:
                        json.dump(data, f, indent=2, default=str)
                
                else:
                    raise ValueError(f"Unsupported export format: {format}")
                
                self.logger.info(f"Data exported to: {output_path}")
                
        except Exception as e:
            self.logger.error(f"Failed to export data: {e}")
            raise DataError(
                "Failed to export data",
                error_code="EXPORT_FAILED",
                cause=e
            )
    
    def close(self) -> None:
        """Close database connections"""
        # SQLite connections are automatically closed when using context managers
        self.logger.info("Database connections closed")
