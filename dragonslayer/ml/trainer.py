"""
Model Trainer
=============

Unified model training component for machine learning models.

This module consolidates training functionality from multiple implementations
into a single, production-ready trainer with support for various backends.
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union, Callable
import numpy as np

from ..core.exceptions import MLError, ConfigurationError
from ..core.config import VMDragonSlayerConfig

logger = logging.getLogger(__name__)

# Handle optional dependencies
try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    from torch.utils.data import DataLoader, TensorDataset
    import torch.distributed as dist
    from torch.nn.parallel import DistributedDataParallel as DDP
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    DDP = None
    logger.warning("PyTorch not available, some training features disabled")

try:
    from sklearn.model_selection import train_test_split, cross_val_score
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
    import joblib
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    logger.warning("Scikit-learn not available, some training features disabled")


@dataclass
class TrainingConfig:
    """Configuration for model training."""
    batch_size: int = 32
    learning_rate: float = 0.001
    epochs: int = 100
    validation_split: float = 0.2
    early_stopping_patience: int = 10
    use_gpu: bool = True
    mixed_precision: bool = True
    save_checkpoints: bool = True
    checkpoint_dir: str = "models/checkpoints"
    log_interval: int = 10
    
    # Advanced training options
    optimizer: str = "adam"  # adam, sgd, rmsprop
    scheduler: str = "cosine"  # cosine, step, plateau
    weight_decay: float = 1e-4
    gradient_clipping: float = 1.0
    
    # GPU and distributed training
    distributed: bool = False
    world_size: int = 1
    rank: int = 0
    backend: str = 'nccl'
    init_method: str = 'env://'
    target_accuracy: float = 0.95
    label_smoothing: float = 0.1
    gradient_accumulation_steps: int = 1
    
    # Data augmentation
    use_augmentation: bool = False
    augmentation_strength: float = 0.1
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary."""
        return {
            'batch_size': self.batch_size,
            'learning_rate': self.learning_rate,
            'epochs': self.epochs,
            'validation_split': self.validation_split,
            'early_stopping_patience': self.early_stopping_patience,
            'use_gpu': self.use_gpu,
            'mixed_precision': self.mixed_precision,
            'save_checkpoints': self.save_checkpoints,
            'checkpoint_dir': self.checkpoint_dir,
            'log_interval': self.log_interval,
            'optimizer': self.optimizer,
            'scheduler': self.scheduler,
            'weight_decay': self.weight_decay,
            'gradient_clipping': self.gradient_clipping,
            'distributed': self.distributed,
            'world_size': self.world_size,
            'rank': self.rank,
            'backend': self.backend,
            'target_accuracy': self.target_accuracy,
            'label_smoothing': self.label_smoothing,
            'gradient_accumulation_steps': self.gradient_accumulation_steps,
            'use_augmentation': self.use_augmentation,
            'augmentation_strength': self.augmentation_strength
        }


@dataclass
class TrainingMetrics:
    """Training metrics and history."""
    epoch: int
    train_loss: float
    val_loss: float
    train_accuracy: float
    val_accuracy: float
    learning_rate: float
    epoch_time: float
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary."""
        return {
            'epoch': self.epoch,
            'train_loss': self.train_loss,
            'val_loss': self.val_loss,
            'train_accuracy': self.train_accuracy,
            'val_accuracy': self.val_accuracy,
            'learning_rate': self.learning_rate,
            'epoch_time': self.epoch_time,
            'timestamp': self.timestamp.isoformat()
        }


class ModelTrainer:
    """
    Unified model trainer supporting multiple ML backends.
    
    This trainer consolidates training functionality from multiple implementations
    and provides a clean interface for training both PyTorch and scikit-learn models.
    """
    
    def __init__(self, config: Optional[TrainingConfig] = None):
        self.config = config or TrainingConfig()
        self.device = self._setup_device()
        self.training_history: List[TrainingMetrics] = []
        self.best_model_path: Optional[str] = None
        self.best_val_accuracy = 0.0
        
        # Setup mixed precision if available
        self.scaler = None
        if TORCH_AVAILABLE and self.config.use_gpu and self.config.mixed_precision:
            try:
                self.scaler = torch.cuda.amp.GradScaler()
                logger.info("Mixed precision training enabled")
            except Exception as e:
                logger.warning(f"Failed to enable mixed precision: {e}")
        
        # Create checkpoint directory
        Path(self.config.checkpoint_dir).mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Initialized ModelTrainer with device: {self.device}")
    
    def _setup_device(self) -> str:
        """Setup training device."""
        if not self.config.use_gpu:
            return "cpu"
        
        if TORCH_AVAILABLE and torch.cuda.is_available():
            device_count = torch.cuda.device_count()
            logger.info(f"CUDA available with {device_count} GPU(s)")
            
            if device_count > 1:
                # Select GPU with most memory
                gpu_memory = []
                for i in range(device_count):
                    props = torch.cuda.get_device_properties(i)
                    gpu_memory.append(props.total_memory)
                
                best_gpu = np.argmax(gpu_memory)
                device = f"cuda:{best_gpu}"
                memory_gb = gpu_memory[best_gpu] / 1e9
                logger.info(f"Selected GPU {best_gpu} with {memory_gb:.1f}GB memory")
            else:
                device = "cuda:0"
            
            # Optimize CUDA settings
            if TORCH_AVAILABLE:
                torch.backends.cudnn.benchmark = True
                torch.backends.cudnn.deterministic = False
            
            return device
        else:
            logger.info("GPU not available, using CPU")
            return "cpu"
    
    def train_pytorch_model(self,
                          model: Any,
                          train_data: Tuple[np.ndarray, np.ndarray],
                          val_data: Optional[Tuple[np.ndarray, np.ndarray]] = None,
                          callbacks: Optional[List[Callable]] = None) -> Dict[str, Any]:
        """
        Train a PyTorch model.
        
        Args:
            model: PyTorch model to train
            train_data: Training data (X, y)
            val_data: Validation data (X, y), optional
            callbacks: List of callback functions for training events
            
        Returns:
            Training results and metrics
        """
        if not TORCH_AVAILABLE:
            raise MLError("PyTorch not available for training")
        
        X_train, y_train = train_data
        
        # Split validation data if not provided
        if val_data is None:
            X_train, X_val, y_train, y_val = train_test_split(
                X_train, y_train, 
                test_size=self.config.validation_split,
                random_state=42
            )
        else:
            X_val, y_val = val_data
        
        # Convert to tensors
        X_train_tensor = torch.FloatTensor(X_train)
        y_train_tensor = torch.LongTensor(y_train)
        X_val_tensor = torch.FloatTensor(X_val)
        y_val_tensor = torch.LongTensor(y_val)
        
        # Create data loaders
        train_dataset = TensorDataset(X_train_tensor, y_train_tensor)
        val_dataset = TensorDataset(X_val_tensor, y_val_tensor)
        
        train_loader = DataLoader(
            train_dataset, 
            batch_size=self.config.batch_size, 
            shuffle=True
        )
        val_loader = DataLoader(
            val_dataset, 
            batch_size=self.config.batch_size, 
            shuffle=False
        )
        
        # Move model to device
        model = model.to(self.device)
        
        # Setup optimizer
        optimizer = self._create_optimizer(model)
        scheduler = self._create_scheduler(optimizer)
        criterion = nn.CrossEntropyLoss()
        
        # Training loop
        start_time = time.time()
        patience_counter = 0
        
        for epoch in range(self.config.epochs):
            epoch_start = time.time()
            
            # Training phase
            train_loss, train_acc = self._train_epoch(
                model, train_loader, optimizer, criterion, epoch
            )
            
            # Validation phase
            val_loss, val_acc = self._validate_epoch(
                model, val_loader, criterion
            )
            
            # Learning rate scheduling
            if scheduler:
                scheduler.step(val_loss)
            
            epoch_time = time.time() - epoch_start
            current_lr = optimizer.param_groups[0]['lr']
            
            # Record metrics
            metrics = TrainingMetrics(
                epoch=epoch,
                train_loss=train_loss,
                val_loss=val_loss,
                train_accuracy=train_acc,
                val_accuracy=val_acc,
                learning_rate=current_lr,
                epoch_time=epoch_time
            )
            self.training_history.append(metrics)
            
            # Logging
            if epoch % self.config.log_interval == 0:
                logger.info(
                    f"Epoch {epoch}/{self.config.epochs}: "
                    f"Train Loss: {train_loss:.4f}, Train Acc: {train_acc:.4f}, "
                    f"Val Loss: {val_loss:.4f}, Val Acc: {val_acc:.4f}, "
                    f"LR: {current_lr:.6f}, Time: {epoch_time:.2f}s"
                )
            
            # Save best model
            if val_acc > self.best_val_accuracy:
                self.best_val_accuracy = val_acc
                self.best_model_path = self._save_checkpoint(model, optimizer, epoch, val_acc)
                patience_counter = 0
            else:
                patience_counter += 1
            
            # Early stopping
            if patience_counter >= self.config.early_stopping_patience:
                logger.info(f"Early stopping at epoch {epoch}")
                break
            
            # Call callbacks
            if callbacks:
                for callback in callbacks:
                    callback(epoch, metrics)
        
        total_time = time.time() - start_time
        
        return {
            'total_training_time': total_time,
            'best_val_accuracy': self.best_val_accuracy,
            'best_model_path': self.best_model_path,
            'final_epoch': epoch,
            'training_history': [m.to_dict() for m in self.training_history]
        }
    
    def train_sklearn_model(self,
                          model: Any,
                          train_data: Tuple[np.ndarray, np.ndarray],
                          val_data: Optional[Tuple[np.ndarray, np.ndarray]] = None) -> Dict[str, Any]:
        """
        Train a scikit-learn model.
        
        Args:
            model: Scikit-learn model to train
            train_data: Training data (X, y)
            val_data: Validation data (X, y), optional
            
        Returns:
            Training results and metrics
        """
        if not SKLEARN_AVAILABLE:
            raise MLError("Scikit-learn not available for training")
        
        X_train, y_train = train_data
        
        start_time = time.time()
        
        # Train the model
        logger.info(f"Training {type(model).__name__} on {len(X_train)} samples")
        model.fit(X_train, y_train)
        
        training_time = time.time() - start_time
        
        # Evaluate on training data
        train_pred = model.predict(X_train)
        train_accuracy = accuracy_score(y_train, train_pred)
        
        results = {
            'training_time': training_time,
            'train_accuracy': train_accuracy,
            'model_type': type(model).__name__
        }
        
        # Evaluate on validation data if provided
        if val_data is not None:
            X_val, y_val = val_data
            val_pred = model.predict(X_val)
            val_accuracy = accuracy_score(y_val, val_pred)
            val_precision = precision_score(y_val, val_pred, average='weighted', zero_division=0)
            val_recall = recall_score(y_val, val_pred, average='weighted', zero_division=0)
            val_f1 = f1_score(y_val, val_pred, average='weighted', zero_division=0)
            
            results.update({
                'val_accuracy': val_accuracy,
                'val_precision': val_precision,
                'val_recall': val_recall,
                'val_f1': val_f1
            })
        
        # Save model
        if self.config.save_checkpoints:
            model_path = Path(self.config.checkpoint_dir) / f"sklearn_model_{datetime.now().strftime('%Y%m%d_%H%M%S')}.joblib"
            joblib.dump(model, model_path)
            results['model_path'] = str(model_path)
            logger.info(f"Model saved to {model_path}")
        
        # Cross-validation if validation data not provided
        if val_data is None and len(X_train) > 100:  # Only for larger datasets
            try:
                cv_scores = cross_val_score(model, X_train, y_train, cv=5, scoring='accuracy')
                results['cv_mean_accuracy'] = cv_scores.mean()
                results['cv_std_accuracy'] = cv_scores.std()
                logger.info(f"Cross-validation accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
            except Exception as e:
                logger.warning(f"Cross-validation failed: {e}")
        
        return results
    
    def _train_epoch(self, model, train_loader, optimizer, criterion, epoch):
        """Train one epoch."""
        model.train()
        total_loss = 0.0
        correct = 0
        total = 0
        
        for batch_idx, (data, target) in enumerate(train_loader):
            data, target = data.to(self.device), target.to(self.device)
            
            optimizer.zero_grad()
            
            # Forward pass with mixed precision
            if self.scaler:
                with torch.cuda.amp.autocast():
                    output = model(data)
                    loss = criterion(output, target)
                
                self.scaler.scale(loss).backward()
                
                if self.config.gradient_clipping > 0:
                    self.scaler.unscale_(optimizer)
                    torch.nn.utils.clip_grad_norm_(model.parameters(), self.config.gradient_clipping)
                
                self.scaler.step(optimizer)
                self.scaler.update()
            else:
                output = model(data)
                loss = criterion(output, target)
                loss.backward()
                
                if self.config.gradient_clipping > 0:
                    torch.nn.utils.clip_grad_norm_(model.parameters(), self.config.gradient_clipping)
                
                optimizer.step()
            
            total_loss += loss.item()
            pred = output.argmax(dim=1, keepdim=True)
            correct += pred.eq(target.view_as(pred)).sum().item()
            total += target.size(0)
        
        avg_loss = total_loss / len(train_loader)
        accuracy = correct / total
        return avg_loss, accuracy
    
    def _validate_epoch(self, model, val_loader, criterion):
        """Validate one epoch."""
        model.eval()
        total_loss = 0.0
        correct = 0
        total = 0
        
        with torch.no_grad():
            for data, target in val_loader:
                data, target = data.to(self.device), target.to(self.device)
                output = model(data)
                loss = criterion(output, target)
                
                total_loss += loss.item()
                pred = output.argmax(dim=1, keepdim=True)
                correct += pred.eq(target.view_as(pred)).sum().item()
                total += target.size(0)
        
        avg_loss = total_loss / len(val_loader)
        accuracy = correct / total
        return avg_loss, accuracy
    
    def _create_optimizer(self, model):
        """Create optimizer based on config."""
        if not TORCH_AVAILABLE:
            return None
        
        if self.config.optimizer.lower() == "adam":
            return optim.Adam(
                model.parameters(),
                lr=self.config.learning_rate,
                weight_decay=self.config.weight_decay
            )
        elif self.config.optimizer.lower() == "sgd":
            return optim.SGD(
                model.parameters(),
                lr=self.config.learning_rate,
                momentum=0.9,
                weight_decay=self.config.weight_decay
            )
        elif self.config.optimizer.lower() == "rmsprop":
            return optim.RMSprop(
                model.parameters(),
                lr=self.config.learning_rate,
                weight_decay=self.config.weight_decay
            )
        else:
            logger.warning(f"Unknown optimizer {self.config.optimizer}, using Adam")
            return optim.Adam(
                model.parameters(),
                lr=self.config.learning_rate,
                weight_decay=self.config.weight_decay
            )
    
    def _create_scheduler(self, optimizer):
        """Create learning rate scheduler."""
        if not TORCH_AVAILABLE or not optimizer:
            return None
        
        if self.config.scheduler.lower() == "cosine":
            return optim.lr_scheduler.CosineAnnealingLR(
                optimizer, T_max=self.config.epochs
            )
        elif self.config.scheduler.lower() == "step":
            return optim.lr_scheduler.StepLR(
                optimizer, step_size=30, gamma=0.1
            )
        elif self.config.scheduler.lower() == "plateau":
            return optim.lr_scheduler.ReduceLROnPlateau(
                optimizer, mode='min', patience=5, factor=0.5, verbose=True
            )
        else:
            return None
    
    def _save_checkpoint(self, model, optimizer, epoch, accuracy):
        """Save model checkpoint."""
        if not self.config.save_checkpoints:
            return None
        
        checkpoint_path = Path(self.config.checkpoint_dir) / f"best_model_epoch_{epoch}_acc_{accuracy:.4f}.pth"
        
        checkpoint = {
            'epoch': epoch,
            'model_state_dict': model.state_dict(),
            'optimizer_state_dict': optimizer.state_dict(),
            'accuracy': accuracy,
            'config': self.config.to_dict()
        }
        
        torch.save(checkpoint, checkpoint_path)
        logger.info(f"Checkpoint saved: {checkpoint_path}")
        return str(checkpoint_path)
    
    def load_checkpoint(self, model, checkpoint_path: str, optimizer=None):
        """Load model from checkpoint."""
        if not TORCH_AVAILABLE:
            raise MLError("PyTorch not available for loading checkpoint")
        
        checkpoint = torch.load(checkpoint_path, map_location=self.device)
        model.load_state_dict(checkpoint['model_state_dict'])
        
        if optimizer and 'optimizer_state_dict' in checkpoint:
            optimizer.load_state_dict(checkpoint['optimizer_state_dict'])
        
        logger.info(f"Loaded checkpoint from {checkpoint_path}")
        return checkpoint.get('epoch', 0), checkpoint.get('accuracy', 0.0)
    
    def get_training_summary(self) -> Dict[str, Any]:
        """Get summary of training history."""
        if not self.training_history:
            return {}
        
        latest = self.training_history[-1]
        return {
            'total_epochs': len(self.training_history),
            'final_train_accuracy': latest.train_accuracy,
            'final_val_accuracy': latest.val_accuracy,
            'best_val_accuracy': max(m.val_accuracy for m in self.training_history),
            'training_time': sum(getattr(m, 'epoch_time', 0.0) for m in self.training_history),
            'device': str(self.device),
            'config': self.config.to_dict()
        }


class GPUTrainer:
    """
    Advanced GPU training pipeline with distributed training,
    mixed precision, and performance optimization.
    
    This class consolidates advanced GPU training functionality from:
    - AdvancedGPUTrainer
    - DistributedModelTrainer
    - Enterprise ML Framework components
    """
    
    def __init__(self, config: TrainingConfig):
        self.config = config
        self.device = self._setup_device()
        self.distributed = config.distributed and config.world_size > 1
        self.mixed_precision = config.mixed_precision and torch.cuda.is_available()
        
        # Initialize distributed training if enabled
        if self.distributed and TORCH_AVAILABLE:
            self._setup_distributed()
        
        # Setup mixed precision training
        if self.mixed_precision and TORCH_AVAILABLE:
            self.scaler = torch.cuda.amp.GradScaler()
        else:
            self.scaler = None
        
        # Training metrics tracking
        self.training_metrics = {
            'epoch_times': [],
            'gpu_utilization': [],
            'memory_usage': [],
            'throughput': [],
            'loss_curves': [],
            'accuracy_curves': [],
            'learning_rates': []
        }
        
        # Performance monitoring
        self.start_time = None
        self.total_samples_processed = 0
        
        logger.info(f"GPU Trainer initialized - Device: {self.device}, "
                   f"Distributed: {self.distributed}, Mixed Precision: {self.mixed_precision}")
    
    def _setup_device(self) -> torch.device:
        """Setup optimal device configuration."""
        if not TORCH_AVAILABLE:
            return None
        
        if torch.cuda.is_available() and self.config.use_gpu:
            device = torch.device(f'cuda:{self.config.rank}' if self.distributed else 'cuda')
            logger.info(f"Using GPU device: {device}")
            logger.info(f"GPU Memory: {torch.cuda.get_device_properties(device).total_memory / 1e9:.1f}GB")
        else:
            device = torch.device('cpu')
            logger.info("Using CPU device")
        
        return device
    
    def _setup_distributed(self):
        """Setup distributed training environment."""
        if not TORCH_AVAILABLE:
            return
        
        try:
            import torch.distributed as dist
            
            if not dist.is_available():
                logger.error("Distributed training not available")
                self.distributed = False
                return
            
            # Initialize process group
            if not dist.is_initialized():
                dist.init_process_group(
                    backend=self.config.backend,
                    init_method=self.config.init_method,
                    rank=self.config.rank,
                    world_size=self.config.world_size
                )
            
            # Set device for this process
            if torch.cuda.is_available():
                torch.cuda.set_device(self.config.rank)
                self.device = torch.device(f'cuda:{self.config.rank}')
            
            logger.info(f"Distributed training initialized: rank {self.config.rank}/{self.config.world_size}")
            
        except Exception as e:
            logger.error(f"Failed to setup distributed training: {e}")
            self.distributed = False
    
    async def train_model_advanced(
        self,
        model: nn.Module,
        train_dataloader: DataLoader,
        val_dataloader: DataLoader,
        epochs: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Advanced training with GPU acceleration and optimization.
        
        Args:
            model: Neural network model to train
            train_dataloader: Training data loader
            val_dataloader: Validation data loader  
            epochs: Number of epochs (overrides config)
            
        Returns:
            Training results and metrics
        """
        if not TORCH_AVAILABLE:
            raise MLError("PyTorch not available for GPU training")
        
        epochs = epochs or self.config.epochs
        logger.info("🚀 Starting advanced GPU training pipeline")
        self.start_time = time.time()
        
        # Move model to device
        model.to(self.device)
        
        # Setup distributed model if needed
        if self.distributed:
            model = DDP(model, device_ids=[self.config.rank])
        
        # Setup optimizer with advanced settings
        optimizer = self._setup_optimizer(model)
        scheduler = self._setup_scheduler(optimizer, epochs)
        
        # Loss function with label smoothing
        criterion = nn.CrossEntropyLoss(
            label_smoothing=self.config.label_smoothing
        )
        
        # Training state tracking
        best_val_accuracy = 0.0
        best_model_state = None
        patience_counter = 0
        max_patience = self.config.early_stopping_patience
        
        # Training loop with advanced features
        training_results = {
            'epoch_losses': [],
            'epoch_accuracies': [],
            'validation_losses': [],
            'validation_accuracies': [],
            'best_val_accuracy': 0.0,
            'training_time_seconds': 0.0,
            'gpu_metrics': []
        }
        
        for epoch in range(epochs):
            epoch_start = time.time()
            
            # Training phase
            train_metrics = await self._train_epoch_advanced(
                model, train_dataloader, optimizer, criterion, epoch
            )
            
            # Validation phase
            val_metrics = await self._validate_epoch_advanced(
                model, val_dataloader, criterion, epoch
            )
            
            # Learning rate scheduling
            if isinstance(scheduler, torch.optim.lr_scheduler.ReduceLROnPlateau):
                scheduler.step(val_metrics['loss'])
            else:
                scheduler.step()
            
            epoch_time = time.time() - epoch_start
            self.training_metrics['epoch_times'].append(epoch_time)
            
            # Performance monitoring
            if torch.cuda.is_available():
                gpu_util = self._monitor_gpu_utilization()
                memory_usage = torch.cuda.memory_allocated() / torch.cuda.max_memory_allocated()
                self.training_metrics['gpu_utilization'].append(gpu_util)
                self.training_metrics['memory_usage'].append(memory_usage)
                
                training_results['gpu_metrics'].append({
                    'epoch': epoch,
                    'gpu_utilization': gpu_util,
                    'memory_usage': memory_usage
                })
            
            # Throughput calculation
            samples_per_epoch = len(train_dataloader.dataset)
            throughput = samples_per_epoch / epoch_time
            self.training_metrics['throughput'].append(throughput)
            self.total_samples_processed += samples_per_epoch
            
            # Model checkpointing
            if val_metrics['accuracy'] > best_val_accuracy:
                best_val_accuracy = val_metrics['accuracy']
                best_model_state = model.state_dict().copy()
                patience_counter = 0
                
                # Save best model checkpoint
                if self.config.save_checkpoints:
                    self._save_checkpoint(model, optimizer, epoch, val_metrics)
            else:
                patience_counter += 1
            
            # Record training progress
            training_results['epoch_losses'].append(train_metrics['loss'])
            training_results['epoch_accuracies'].append(train_metrics['accuracy'])
            training_results['validation_losses'].append(val_metrics['loss'])
            training_results['validation_accuracies'].append(val_metrics['accuracy'])
            
            # Logging and monitoring
            if epoch % self.config.log_interval == 0 or epoch == epochs - 1:
                self._log_training_progress(epoch, epochs, train_metrics, val_metrics, 
                                           throughput, epoch_time)
            
            # Early stopping check
            if val_metrics['accuracy'] >= self.config.target_accuracy:
                logger.info(f"🎯 Target accuracy {self.config.target_accuracy:.1%} achieved at epoch {epoch}!")
                break
            
            if patience_counter >= max_patience:
                logger.info(f"⏸️  Early stopping triggered after {max_patience} epochs without improvement")
                break
        
        # Load best model
        if best_model_state is not None:
            model.load_state_dict(best_model_state)
        
        total_training_time = time.time() - self.start_time
        training_results['training_time_seconds'] = total_training_time
        training_results['best_val_accuracy'] = best_val_accuracy
        
        # Generate comprehensive training report
        training_report = self._generate_training_report(
            total_training_time, best_val_accuracy, epochs, training_results
        )
        
        logger.info(f"✅ Advanced training completed in {total_training_time:.2f}s")
        logger.info(f"🏆 Best validation accuracy: {best_val_accuracy:.4f}")
        
        return training_report
    
    def _setup_optimizer(self, model: nn.Module):
        """Setup optimizer with advanced settings."""
        if self.config.optimizer.lower() == 'adamw':
            return torch.optim.AdamW(
                model.parameters(),
                lr=self.config.learning_rate,
                weight_decay=self.config.weight_decay,
                betas=(0.9, 0.999),
                eps=1e-8
            )
        elif self.config.optimizer.lower() == 'adam':
            return torch.optim.Adam(
                model.parameters(),
                lr=self.config.learning_rate,
                weight_decay=self.config.weight_decay
            )
        else:
            return torch.optim.SGD(
                model.parameters(),
                lr=self.config.learning_rate,
                momentum=0.9,
                weight_decay=self.config.weight_decay
            )
    
    def _setup_scheduler(self, optimizer, epochs):
        """Setup advanced learning rate scheduling."""
        if self.config.scheduler == 'cosine':
            return torch.optim.lr_scheduler.CosineAnnealingLR(
                optimizer, T_max=epochs, eta_min=1e-6
            )
        elif self.config.scheduler == 'plateau':
            return torch.optim.lr_scheduler.ReduceLROnPlateau(
                optimizer, mode='min', factor=0.5, patience=5, verbose=True
            )
        elif self.config.scheduler == 'step':
            return torch.optim.lr_scheduler.StepLR(
                optimizer, step_size=epochs//3, gamma=0.1
            )
        else:
            return torch.optim.lr_scheduler.ExponentialLR(
                optimizer, gamma=0.95
            )
    
    async def _train_epoch_advanced(
        self,
        model: nn.Module,
        dataloader: DataLoader,
        optimizer: torch.optim.Optimizer,
        criterion: nn.Module,
        epoch: int
    ) -> Dict[str, float]:
        """Advanced training epoch with mixed precision and optimization."""
        model.train()
        total_loss = 0.0
        correct = 0
        total = 0
        
        for batch_idx, (data, targets) in enumerate(dataloader):
            data, targets = data.to(self.device), targets.to(self.device)
            
            optimizer.zero_grad()
            
            # Mixed precision forward pass
            if self.mixed_precision and self.scaler:
                with torch.cuda.amp.autocast():
                    outputs = model(data)
                    loss = criterion(outputs, targets)
                
                # Scaled backward pass
                self.scaler.scale(loss).backward()
                
                # Gradient clipping
                self.scaler.unscale_(optimizer)
                torch.nn.utils.clip_grad_norm_(model.parameters(), self.config.gradient_clipping)
                
                # Optimizer step
                self.scaler.step(optimizer)
                self.scaler.update()
            else:
                outputs = model(data)
                loss = criterion(outputs, targets)
                loss.backward()
                
                # Gradient clipping
                torch.nn.utils.clip_grad_norm_(model.parameters(), self.config.gradient_clipping)
                optimizer.step()
            
            # Statistics
            total_loss += loss.item()
            _, predicted = torch.max(outputs.data, 1)
            total += targets.size(0)
            correct += (predicted == targets).sum().item()
        
        return {
            'loss': total_loss / len(dataloader),
            'accuracy': correct / total
        }
    
    async def _validate_epoch_advanced(
        self,
        model: nn.Module,
        dataloader: DataLoader,
        criterion: nn.Module,
        epoch: int
    ) -> Dict[str, float]:
        """Advanced validation with detailed metrics."""
        model.eval()
        total_loss = 0.0
        correct = 0
        total = 0
        
        with torch.no_grad():
            for data, targets in dataloader:
                data, targets = data.to(self.device), targets.to(self.device)
                
                if self.mixed_precision:
                    with torch.cuda.amp.autocast():
                        outputs = model(data)
                        loss = criterion(outputs, targets)
                else:
                    outputs = model(data)
                    loss = criterion(outputs, targets)
                
                total_loss += loss.item()
                _, predicted = torch.max(outputs.data, 1)
                total += targets.size(0)
                correct += (predicted == targets).sum().item()
        
        return {
            'loss': total_loss / len(dataloader),
            'accuracy': correct / total
        }
    
    def _monitor_gpu_utilization(self) -> float:
        """Monitor GPU utilization."""
        if not torch.cuda.is_available():
            return 0.0
        
        try:
            # Try to use nvidia-ml-py if available
            import pynvml
            pynvml.nvmlInit()
            handle = pynvml.nvmlDeviceGetHandleByIndex(0)
            util = pynvml.nvmlDeviceGetUtilizationRates(handle)
            return util.gpu / 100.0
        except (ImportError, Exception):
            # Fallback to memory-based estimation
            try:
                allocated = torch.cuda.memory_allocated()
                cached = torch.cuda.memory_reserved()
                return min(allocated / cached, 1.0) if cached > 0 else 0.0
            except Exception:
                return 0.0
    
    def _save_checkpoint(self, model, optimizer, epoch, metrics):
        """Save model checkpoint with metadata."""
        if not self.config.save_checkpoints:
            return
        
        checkpoint_dir = Path(self.config.checkpoint_dir)
        checkpoint_dir.mkdir(parents=True, exist_ok=True)
        
        checkpoint_path = checkpoint_dir / f"gpu_model_epoch_{epoch}.pt"
        
        checkpoint = {
            'epoch': epoch,
            'model_state_dict': model.state_dict(),
            'optimizer_state_dict': optimizer.state_dict(),
            'metrics': metrics,
            'config': self.config.to_dict(),
            'training_metrics': self.training_metrics
        }
        
        torch.save(checkpoint, checkpoint_path)
        logger.info(f"GPU checkpoint saved: {checkpoint_path}")
    
    def _log_training_progress(self, epoch, total_epochs, train_metrics, val_metrics, 
                              throughput, epoch_time):
        """Log detailed training progress."""
        logger.info(
            f"Epoch {epoch+1}/{total_epochs} - "
            f"Train Loss: {train_metrics['loss']:.4f}, "
            f"Train Acc: {train_metrics['accuracy']:.4f}, "
            f"Val Loss: {val_metrics['loss']:.4f}, "
            f"Val Acc: {val_metrics['accuracy']:.4f}, "
            f"Time: {epoch_time:.2f}s, "
            f"Throughput: {throughput:.1f} samples/s"
        )
        
        if torch.cuda.is_available():
            memory_used = torch.cuda.memory_allocated() / 1e9
            memory_cached = torch.cuda.memory_reserved() / 1e9
            logger.info(f"GPU Memory: {memory_used:.1f}GB used, {memory_cached:.1f}GB cached")
    
    def _generate_training_report(self, total_time, best_accuracy, epochs, results) -> Dict[str, Any]:
        """Generate comprehensive training report."""
        report = {
            'training_completed': True,
            'total_training_time_seconds': total_time,
            'best_validation_accuracy': best_accuracy,
            'total_epochs': epochs,
            'samples_processed': self.total_samples_processed,
            'average_throughput': sum(self.training_metrics['throughput']) / len(self.training_metrics['throughput']) if self.training_metrics['throughput'] else 0,
            'device_info': {
                'device': str(self.device),
                'distributed': self.distributed,
                'mixed_precision': self.mixed_precision,
                'world_size': self.config.world_size,
                'rank': self.config.rank
            },
            'performance_metrics': {
                'average_epoch_time': sum(self.training_metrics['epoch_times']) / len(self.training_metrics['epoch_times']) if self.training_metrics['epoch_times'] else 0,
                'peak_gpu_utilization': max(self.training_metrics['gpu_utilization']) if self.training_metrics['gpu_utilization'] else 0,
                'peak_memory_usage': max(self.training_metrics['memory_usage']) if self.training_metrics['memory_usage'] else 0,
                'peak_throughput': max(self.training_metrics['throughput']) if self.training_metrics['throughput'] else 0
            },
            'config': self.config.to_dict(),
            'detailed_results': results
        }
        
        return report
        if not self.training_history:
            return {'status': 'no_training_history'}
        
        best_metrics = max(self.training_history, key=lambda x: x.val_accuracy)
        latest_metrics = self.training_history[-1]
        
        return {
            'total_epochs': len(self.training_history),
            'best_val_accuracy': best_metrics.val_accuracy,
            'best_epoch': best_metrics.epoch,
            'final_train_accuracy': latest_metrics.train_accuracy,
            'final_val_accuracy': latest_metrics.val_accuracy,
            'total_training_time': sum(m.epoch_time for m in self.training_history),
            'best_model_path': self.best_model_path,
            'config': self.config.to_dict()
        }
