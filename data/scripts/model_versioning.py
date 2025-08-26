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
Model Versioning and Registry Management Script
==============================================

Manages model versions, tracks lineage, and maintains performance history.
"""

import argparse
import hashlib
import json
import logging
import os
import shutil
import sqlite3
import subprocess
import sys
import toml
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ModelVersionManager:
    """Manages model versions, lineage, and performance tracking"""
    
    def __init__(self, config_path: str = "data/models/model_registry_config.toml"):
        self.config_path = config_path
        self.config = self._load_config()
        self.db_path = self.config['database']['path']
        self._initialize_database()
        
        if self.config['version_control_system']['enabled']:
            self._initialize_git()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from TOML file"""
        try:
            with open(self.config_path, 'r') as f:
                return toml.load(f)
        except Exception as e:
            logger.error(f"Failed to load config {self.config_path}: {e}")
            return self._default_config()
    
    def _default_config(self) -> Dict[str, Any]:
        """Return default configuration"""
        return {
            'database': {'path': 'data/models/model_registry.db'},
            'version_control_system': {'enabled': False},
            'model_lineage_tracking': {'enabled': True},
            'performance_metrics_history': {'enabled': True}
        }
    
    def _initialize_database(self):
        """Initialize SQLite database with required tables"""
        os.makedirs(Path(self.db_path).parent, exist_ok=True)
        
        with sqlite3.connect(self.db_path) as conn:
            # Create tables from config
            for section_key, section in self.config.items():
                if isinstance(section, dict) and 'table_name' in section and 'schema' in section:
                    logger.info(f"Creating table: {section['table_name']}")
                    conn.executescript(section['schema'])
            
            # Create indexes for performance
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_model_registry_model_id ON model_registry(model_id);
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_model_registry_status ON model_registry(status);
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_model_versions_model_id ON model_versions(model_id);
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_performance_metrics_model_id ON model_performance(model_id);
            """)
            
            conn.commit()
        
        logger.info(f"Database initialized: {self.db_path}")
    
    def _initialize_git(self):
        """Initialize Git repository for model versioning"""
        git_config = self.config['version_control_system']
        repo_path = git_config.get('git_repository', 'models/.git')
        
        models_dir = Path('data/models')
        models_dir.mkdir(exist_ok=True)
        
        if not (models_dir / '.git').exists():
            try:
                subprocess.run(['git', 'init'], cwd=models_dir, check=True)
                subprocess.run(['git', 'config', 'user.name', 'VMDragonSlayer'], cwd=models_dir, check=True)
                subprocess.run(['git', 'config', 'user.email', 'vmdragonslayer@system'], cwd=models_dir, check=True)
                logger.info("Git repository initialized for model versioning")
            except subprocess.CalledProcessError as e:
                logger.warning(f"Failed to initialize Git repository: {e}")
    
    def register_model(self, model_info: Dict[str, Any]) -> str:
        """Register a new model in the registry"""
        
        # Generate model ID if not provided
        if 'model_id' not in model_info:
            model_info['model_id'] = self._generate_model_id(model_info)
        
        # Calculate file checksum
        model_path = model_info.get('file_path')
        if model_path and Path(model_path).exists():
            model_info['checksum'] = self._calculate_checksum(model_path)
            model_info['file_size'] = Path(model_path).stat().st_size
        
        # Set timestamps
        now = datetime.utcnow().isoformat()
        model_info.setdefault('created_date', now)
        model_info.setdefault('last_updated', now)
        
        # Git commit hash (if Git is enabled)
        if self.config['version_control_system']['enabled']:
            model_info['git_commit_hash'] = self._get_git_commit_hash()
        
        with sqlite3.connect(self.db_path) as conn:
            # Insert model record
            cursor = conn.cursor()
            
            columns = [
                'model_id', 'model_name', 'model_type', 'version', 'parent_model_id',
                'file_path', 'file_size', 'created_date', 'last_updated',
                'accuracy', 'precision_score', 'recall', 'f1_score',
                'training_samples', 'validation_samples', 'feature_count',
                'model_parameters', 'training_config', 'feature_config', 'metadata',
                'status', 'checksum', 'git_commit_hash', 'created_by', 'tags',
                'deployment_ready', 'benchmark_score', 'model_complexity'
            ]
            
            values = [model_info.get(col) for col in columns]
            placeholders = ','.join(['?' for _ in columns])
            
            cursor.execute(f"""
                INSERT OR REPLACE INTO model_registry ({','.join(columns)})
                VALUES ({placeholders})
            """, values)
            
            # Create version record
            self._create_version_record(conn, model_info)
            
            conn.commit()
        
        logger.info(f"Registered model: {model_info['model_id']} v{model_info.get('version', '1.0.0')}")
        
        # Auto-commit to Git if enabled
        if self.config['version_control_system']['enabled'] and self.config['version_control_system']['auto_commit']:
            self._git_commit_model(model_info)
        
        return model_info['model_id']
    
    def update_model_performance(self, model_id: str, metrics: Dict[str, Any]):
        """Update model performance metrics"""
        
        now = datetime.utcnow().isoformat()
        metrics.setdefault('test_date', now)
        metrics['model_id'] = model_id
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Insert performance record
            columns = [
                'model_id', 'test_date', 'test_dataset_size', 'accuracy',
                'precision_score', 'recall', 'f1_score', 'inference_time_ms',
                'memory_usage_mb', 'test_config', 'notes'
            ]
            
            values = [metrics.get(col) for col in columns]
            placeholders = ','.join(['?' for _ in columns])
            
            cursor.execute(f"""
                INSERT INTO model_performance ({','.join(columns)})
                VALUES ({placeholders})
            """, values)
            
            # Update model registry with latest metrics
            cursor.execute("""
                UPDATE model_registry 
                SET accuracy = ?, precision_score = ?, recall = ?, f1_score = ?,
                    last_updated = ?
                WHERE model_id = ?
            """, [
                metrics.get('accuracy'), metrics.get('precision_score'),
                metrics.get('recall'), metrics.get('f1_score'),
                now, model_id
            ])
            
            conn.commit()
        
        logger.info(f"Updated performance metrics for model: {model_id}")
    
    def track_model_lineage(self, child_model_id: str, parent_model_id: str, 
                           relationship_type: str = 'derived_from', 
                           influence_weight: float = 1.0, metadata: Dict = None):
        """Track lineage between models"""
        
        if not self.config.get('model_lineage_tracking', {}).get('enabled', True):
            return
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR IGNORE INTO model_lineage 
                (child_model_id, parent_model_id, relationship_type, influence_weight, created_date, metadata)
                VALUES (?, ?, ?, ?, ?, ?)
            """, [
                child_model_id, parent_model_id, relationship_type, influence_weight,
                datetime.utcnow().isoformat(), json.dumps(metadata or {})
            ])
            conn.commit()
        
        logger.info(f"Tracked lineage: {child_model_id} <- {parent_model_id} ({relationship_type})")
    
    def create_model_version(self, model_id: str, version: str, changelog: str = "", 
                           version_type: str = "minor") -> bool:
        """Create a new version of an existing model"""
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Get current model info
            cursor.execute("SELECT * FROM model_registry WHERE model_id = ?", [model_id])
            model_record = cursor.fetchone()
            
            if not model_record:
                logger.error(f"Model not found: {model_id}")
                return False
            
            # Create version record
            now = datetime.utcnow().isoformat()
            git_commit = self._get_git_commit_hash() if self.config['version_control_system']['enabled'] else None
            
            cursor.execute("""
                INSERT INTO model_versions 
                (model_id, version, version_type, changelog, created_date, file_path, 
                 file_size, checksum, git_commit_hash, backward_compatible)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, [
                model_id, version, version_type, changelog, now,
                model_record[6],  # file_path from model_registry
                model_record[7],  # file_size
                model_record[19], # checksum
                git_commit, True  # assume backward compatible by default
            ])
            
            # Update model registry version
            cursor.execute("""
                UPDATE model_registry SET version = ?, last_updated = ? WHERE model_id = ?
            """, [version, now, model_id])
            
            conn.commit()
        
        logger.info(f"Created version {version} for model {model_id}")
        return True
    
    def get_model_info(self, model_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed model information"""
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM model_registry WHERE model_id = ?", [model_id])
            model_record = cursor.fetchone()
            
            if not model_record:
                return None
            
            model_info = dict(model_record)
            
            # Get version history
            cursor.execute("""
                SELECT * FROM model_versions WHERE model_id = ? ORDER BY created_date DESC
            """, [model_id])
            model_info['version_history'] = [dict(row) for row in cursor.fetchall()]
            
            # Get performance history
            cursor.execute("""
                SELECT * FROM model_performance WHERE model_id = ? ORDER BY test_date DESC LIMIT 10
            """, [model_id])
            model_info['performance_history'] = [dict(row) for row in cursor.fetchall()]
            
            # Get lineage information
            cursor.execute("""
                SELECT * FROM model_lineage WHERE child_model_id = ? OR parent_model_id = ?
            """, [model_id, model_id])
            model_info['lineage'] = [dict(row) for row in cursor.fetchall()]
        
        return model_info
    
    def list_models(self, status: str = None, model_type: str = None) -> List[Dict[str, Any]]:
        """List models with optional filtering"""
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            query = "SELECT * FROM model_registry"
            params = []
            conditions = []
            
            if status:
                conditions.append("status = ?")
                params.append(status)
            
            if model_type:
                conditions.append("model_type = ?")
                params.append(model_type)
            
            if conditions:
                query += " WHERE " + " AND ".join(conditions)
            
            query += " ORDER BY created_date DESC"
            
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
    
    def deprecate_model(self, model_id: str, replacement_model_id: str = None):
        """Mark a model as deprecated"""
        
        with sqlite3.connect(self.db_path) as conn:
            now = datetime.utcnow().isoformat()
            
            conn.execute("""
                UPDATE model_registry 
                SET status = 'deprecated', last_updated = ? 
                WHERE model_id = ?
            """, [now, model_id])
            
            if replacement_model_id:
                # Create version record indicating replacement
                conn.execute("""
                    INSERT INTO model_versions 
                    (model_id, version, version_type, changelog, created_date, 
                     deprecated, replacement_version)
                    VALUES (?, (SELECT version FROM model_registry WHERE model_id = ?),
                            'deprecation', 'Model deprecated', ?, TRUE, ?)
                """, [model_id, model_id, now, replacement_model_id])
            
            conn.commit()
        
        logger.info(f"Deprecated model: {model_id}")
    
    def backup_registry(self) -> str:
        """Create a backup of the model registry"""
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = f"{self.db_path}.backup.{timestamp}"
        
        shutil.copy2(self.db_path, backup_path)
        logger.info(f"Registry backed up to: {backup_path}")
        
        return backup_path
    
    def _generate_model_id(self, model_info: Dict[str, Any]) -> str:
        """Generate a unique model ID"""
        base = f"{model_info.get('model_name', 'model')}_{model_info.get('model_type', 'classifier')}"
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"{base}_{timestamp}".lower().replace(' ', '_')
    
    def _calculate_checksum(self, file_path: str) -> str:
        """Calculate SHA256 checksum of a file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    
    def _get_git_commit_hash(self) -> Optional[str]:
        """Get current Git commit hash"""
        try:
            result = subprocess.run(
                ['git', 'rev-parse', 'HEAD'], 
                cwd='data/models', 
                capture_output=True, 
                text=True, 
                check=True
            )
            return result.stdout.strip()
        except (subprocess.CalledProcessError, FileNotFoundError):
            return None
    
    def _create_version_record(self, conn: sqlite3.Connection, model_info: Dict[str, Any]):
        """Create initial version record for a new model"""
        
        version = model_info.get('version', '1.0.0')
        
        conn.execute("""
            INSERT INTO model_versions 
            (model_id, version, version_type, changelog, created_date, file_path, 
             file_size, checksum, git_commit_hash)
            VALUES (?, ?, 'major', 'Initial version', ?, ?, ?, ?, ?)
        """, [
            model_info['model_id'], version, model_info.get('created_date'),
            model_info.get('file_path'), model_info.get('file_size'),
            model_info.get('checksum'), model_info.get('git_commit_hash')
        ])
    
    def _git_commit_model(self, model_info: Dict[str, Any]):
        """Commit model to Git repository"""
        
        try:
            models_dir = Path('data/models')
            
            # Add model file
            if model_info.get('file_path'):
                subprocess.run(['git', 'add', model_info['file_path']], cwd=models_dir, check=True)
            
            # Commit with template message
            git_config = self.config['version_control_system']
            commit_msg = git_config.get('commit_message_template', 'Update model {model_name} v{version}').format(**model_info)
            
            subprocess.run(['git', 'commit', '-m', commit_msg], cwd=models_dir, check=True)
            
            # Create tag if configured
            if git_config.get('tag_format'):
                tag = git_config['tag_format'].format(**model_info)
                subprocess.run(['git', 'tag', tag], cwd=models_dir, check=True)
            
            logger.info(f"Committed model to Git: {commit_msg}")
            
        except subprocess.CalledProcessError as e:
            logger.warning(f"Git commit failed: {e}")


def main():
    """Main CLI interface for model version management"""
    
    parser = argparse.ArgumentParser(description="VMDragonSlayer Model Version Manager")
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Register model
    register_parser = subparsers.add_parser('register', help='Register a new model')
    register_parser.add_argument('--name', required=True, help='Model name')
    register_parser.add_argument('--type', required=True, help='Model type')
    register_parser.add_argument('--version', default='1.0.0', help='Model version')
    register_parser.add_argument('--path', required=True, help='Path to model file')
    register_parser.add_argument('--accuracy', type=float, help='Model accuracy')
    register_parser.add_argument('--config', help='Training config JSON file')
    
    # List models
    list_parser = subparsers.add_parser('list', help='List models')
    list_parser.add_argument('--status', help='Filter by status')
    list_parser.add_argument('--type', help='Filter by model type')
    
    # Model info
    info_parser = subparsers.add_parser('info', help='Get model information')
    info_parser.add_argument('model_id', help='Model ID')
    
    # Update performance
    perf_parser = subparsers.add_parser('update-performance', help='Update model performance')
    perf_parser.add_argument('model_id', help='Model ID')
    perf_parser.add_argument('--accuracy', type=float, required=True, help='Accuracy score')
    perf_parser.add_argument('--precision', type=float, help='Precision score')
    perf_parser.add_argument('--recall', type=float, help='Recall score')
    perf_parser.add_argument('--f1', type=float, help='F1 score')
    
    # Create version
    version_parser = subparsers.add_parser('create-version', help='Create new model version')
    version_parser.add_argument('model_id', help='Model ID')
    version_parser.add_argument('version', help='New version number')
    version_parser.add_argument('--changelog', default='', help='Version changelog')
    version_parser.add_argument('--type', default='minor', choices=['major', 'minor', 'patch'], help='Version type')
    
    # Deprecate model
    deprecate_parser = subparsers.add_parser('deprecate', help='Deprecate a model')
    deprecate_parser.add_argument('model_id', help='Model ID to deprecate')
    deprecate_parser.add_argument('--replacement', help='Replacement model ID')
    
    # Backup
    subparsers.add_parser('backup', help='Create registry backup')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    try:
        manager = ModelVersionManager()
        
        if args.command == 'register':
            model_info = {
                'model_name': args.name,
                'model_type': args.type,
                'version': args.version,
                'file_path': args.path,
                'accuracy': args.accuracy
            }
            
            if args.config and Path(args.config).exists():
                with open(args.config) as f:
                    model_info['training_config'] = f.read()
            
            model_id = manager.register_model(model_info)
            print(f"Registered model: {model_id}")
        
        elif args.command == 'list':
            models = manager.list_models(status=args.status, model_type=args.type)
            
            if models:
                print(f"{'Model ID':<30} {'Name':<20} {'Type':<15} {'Version':<10} {'Status':<10} {'Accuracy':<10}")
                print("-" * 100)
                
                for model in models:
                    print(f"{model['model_id']:<30} {model['model_name']:<20} {model['model_type']:<15} "
                          f"{model['version']:<10} {model['status']:<10} {model.get('accuracy', 'N/A'):<10}")
            else:
                print("No models found")
        
        elif args.command == 'info':
            model_info = manager.get_model_info(args.model_id)
            
            if model_info:
                print(f"Model ID: {model_info['model_id']}")
                print(f"Name: {model_info['model_name']}")
                print(f"Type: {model_info['model_type']}")
                print(f"Version: {model_info['version']}")
                print(f"Status: {model_info['status']}")
                print(f"Accuracy: {model_info.get('accuracy', 'N/A')}")
                print(f"Created: {model_info['created_date']}")
                print(f"Updated: {model_info['last_updated']}")
                
                if model_info.get('version_history'):
                    print(f"\nVersion History ({len(model_info['version_history'])} versions):")
                    for version in model_info['version_history'][:5]:  # Show last 5
                        print(f"  v{version['version']} ({version['version_type']}) - {version['created_date']}")
                
                if model_info.get('performance_history'):
                    print(f"\nRecent Performance ({len(model_info['performance_history'])} tests):")
                    for perf in model_info['performance_history'][:3]:  # Show last 3
                        print(f"  {perf['test_date']}: accuracy={perf.get('accuracy', 'N/A')}")
            else:
                print(f"Model not found: {args.model_id}")
        
        elif args.command == 'update-performance':
            metrics = {
                'accuracy': args.accuracy,
                'precision_score': args.precision,
                'recall': args.recall,
                'f1_score': args.f1
            }
            
            manager.update_model_performance(args.model_id, metrics)
            print(f"Updated performance metrics for: {args.model_id}")
        
        elif args.command == 'create-version':
            success = manager.create_model_version(args.model_id, args.version, args.changelog, args.type)
            if success:
                print(f"Created version {args.version} for model {args.model_id}")
            else:
                print(f"Failed to create version for model {args.model_id}")
        
        elif args.command == 'deprecate':
            manager.deprecate_model(args.model_id, args.replacement)
            print(f"Deprecated model: {args.model_id}")
        
        elif args.command == 'backup':
            backup_path = manager.backup_registry()
            print(f"Registry backed up to: {backup_path}")
        
    except Exception as e:
        logger.error(f"Command failed: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
