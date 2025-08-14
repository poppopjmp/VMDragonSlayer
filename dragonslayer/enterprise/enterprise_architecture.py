#!/usr/bin/env python3
"""
Enterprise Architecture Module for VMDragonSlayer
===============================================

Provides enterprise architecture patterns and components including:
    - Service mesh management
    - Load balancing and traffic management
    - Message broker integration
    - Microservices orchestration
    - API gateway functionality
    - Circuit breaker patterns
    - Health monitoring and metrics
    - Distributed tracing

This module consolidates enterprise architecture functionality
from the original enterprise modules.
"""

import asyncio
import json
import logging
import time
import threading
from typing import Dict, List, Optional, Any, Set, Tuple, Callable
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
import uuid
import hashlib

# Core dependencies
try:
    import aiohttp
    import asyncio
    ASYNC_AVAILABLE = True
except ImportError:
    ASYNC_AVAILABLE = False

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

try:
    import pika  # RabbitMQ
    RABBITMQ_AVAILABLE = True
except ImportError:
    RABBITMQ_AVAILABLE = False

# Configure logging
logger = logging.getLogger(__name__)


class ArchitecturePattern(Enum):
    """Enterprise architecture patterns"""
    MICROSERVICES = "microservices"
    SERVICE_MESH = "service_mesh" 
    EVENT_DRIVEN = "event_driven"
    CQRS = "cqrs"
    SAGA = "saga"
    API_GATEWAY = "api_gateway"
    CIRCUIT_BREAKER = "circuit_breaker"
    BULKHEAD = "bulkhead"


class ServiceStatus(Enum):
    """Service health status"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class LoadBalancingAlgorithm(Enum):
    """Load balancing algorithms"""
    ROUND_ROBIN = "round_robin"
    WEIGHTED_ROUND_ROBIN = "weighted_round_robin"
    LEAST_CONNECTIONS = "least_connections"
    LEAST_RESPONSE_TIME = "least_response_time"
    RANDOM = "random"
    HASH = "hash"


@dataclass
class ServiceInstance:
    """Service instance configuration"""
    id: str
    name: str
    host: str
    port: int
    health_check_url: str = "/health"
    weight: int = 1
    status: ServiceStatus = ServiceStatus.UNKNOWN
    last_health_check: datetime = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}
        if not self.id:
            self.id = str(uuid.uuid4())


@dataclass
class HealthCheckResult:
    """Health check result"""
    service_id: str
    status: ServiceStatus
    response_time: float
    timestamp: datetime
    details: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.details is None:
            self.details = {}


@dataclass
class CircuitBreakerConfig:
    """Circuit breaker configuration"""
    failure_threshold: int = 5
    timeout: int = 60  # seconds
    success_threshold: int = 3
    reset_timeout: int = 30


class CircuitBreakerState(Enum):
    """Circuit breaker states"""
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreaker:
    """Circuit breaker implementation"""
    
    def __init__(self, config: CircuitBreakerConfig):
        self.config = config
        self.state = CircuitBreakerState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time = None
        self.lock = threading.Lock()
    
    def call(self, func: Callable, *args, **kwargs):
        """Call function through circuit breaker"""
        with self.lock:
            if self.state == CircuitBreakerState.OPEN:
                if self._should_attempt_reset():
                    self.state = CircuitBreakerState.HALF_OPEN
                    self.success_count = 0
                else:
                    raise Exception("Circuit breaker is OPEN")
            
            try:
                result = func(*args, **kwargs)
                self._on_success()
                return result
            except Exception as e:
                self._on_failure()
                raise e
    
    def _should_attempt_reset(self) -> bool:
        """Check if circuit breaker should attempt reset"""
        if self.last_failure_time is None:
            return False
        
        return (time.time() - self.last_failure_time) > self.config.reset_timeout
    
    def _on_success(self):
        """Handle successful call"""
        if self.state == CircuitBreakerState.HALF_OPEN:
            self.success_count += 1
            if self.success_count >= self.config.success_threshold:
                self.state = CircuitBreakerState.CLOSED
                self.failure_count = 0
                self.success_count = 0
        else:
            self.failure_count = 0
    
    def _on_failure(self):
        """Handle failed call"""
        self.failure_count += 1
        self.last_failure_time = time.time()
        
        if self.failure_count >= self.config.failure_threshold:
            self.state = CircuitBreakerState.OPEN


class LoadBalancer:
    """Load balancer for service instances"""
    
    def __init__(self, algorithm: LoadBalancingAlgorithm = LoadBalancingAlgorithm.ROUND_ROBIN):
        self.algorithm = algorithm
        self.instances: List[ServiceInstance] = []
        self.current_index = 0
        self.lock = threading.Lock()
        self.connection_counts: Dict[str, int] = {}
    
    def add_instance(self, instance: ServiceInstance):
        """Add service instance"""
        with self.lock:
            self.instances.append(instance)
            self.connection_counts[instance.id] = 0
        logger.info(f"Added service instance: {instance.name}:{instance.port}")
    
    def remove_instance(self, instance_id: str):
        """Remove service instance"""
        with self.lock:
            self.instances = [inst for inst in self.instances if inst.id != instance_id]
            if instance_id in self.connection_counts:
                del self.connection_counts[instance_id]
        logger.info(f"Removed service instance: {instance_id}")
    
    def get_next_instance(self) -> Optional[ServiceInstance]:
        """Get next service instance based on algorithm"""
        healthy_instances = [
            inst for inst in self.instances 
            if inst.status == ServiceStatus.HEALTHY
        ]
        
        if not healthy_instances:
            return None
        
        with self.lock:
            if self.algorithm == LoadBalancingAlgorithm.ROUND_ROBIN:
                instance = healthy_instances[self.current_index % len(healthy_instances)]
                self.current_index += 1
                return instance
            
            elif self.algorithm == LoadBalancingAlgorithm.WEIGHTED_ROUND_ROBIN:
                # Simple weighted implementation
                weights = [inst.weight for inst in healthy_instances]
                total_weight = sum(weights)
                
                import random
                rand_val = random.randint(1, total_weight)
                current_weight = 0
                
                for instance in healthy_instances:
                    current_weight += instance.weight
                    if rand_val <= current_weight:
                        return instance
                
                return healthy_instances[0]
            
            elif self.algorithm == LoadBalancingAlgorithm.LEAST_CONNECTIONS:
                # Return instance with least connections
                min_connections = min(
                    self.connection_counts.get(inst.id, 0) 
                    for inst in healthy_instances
                )
                for instance in healthy_instances:
                    if self.connection_counts.get(instance.id, 0) == min_connections:
                        return instance
            
            elif self.algorithm == LoadBalancingAlgorithm.RANDOM:
                import random
                return random.choice(healthy_instances)
            
            else:
                # Default to round robin
                instance = healthy_instances[self.current_index % len(healthy_instances)]
                self.current_index += 1
                return instance
    
    def start_connection(self, instance_id: str):
        """Track connection start"""
        with self.lock:
            if instance_id in self.connection_counts:
                self.connection_counts[instance_id] += 1
    
    def end_connection(self, instance_id: str):
        """Track connection end"""
        with self.lock:
            if instance_id in self.connection_counts:
                self.connection_counts[instance_id] = max(0, self.connection_counts[instance_id] - 1)


class HealthMonitor:
    """Health monitoring for services"""
    
    def __init__(self, check_interval: int = 30):
        self.check_interval = check_interval
        self.services: Dict[str, ServiceInstance] = {}
        self.health_results: Dict[str, HealthCheckResult] = {}
        self.monitoring = False
        self.monitor_thread = None
        self.callbacks: List[Callable[[HealthCheckResult], None]] = []
    
    def add_service(self, service: ServiceInstance):
        """Add service to monitor"""
        self.services[service.id] = service
        logger.info(f"Added service to health monitoring: {service.name}")
    
    def remove_service(self, service_id: str):
        """Remove service from monitoring"""
        if service_id in self.services:
            del self.services[service_id]
        if service_id in self.health_results:
            del self.health_results[service_id]
    
    def add_callback(self, callback: Callable[[HealthCheckResult], None]):
        """Add health check callback"""
        self.callbacks.append(callback)
    
    def start_monitoring(self):
        """Start health monitoring"""
        if self.monitoring:
            return
        
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        logger.info("Started health monitoring")
    
    def stop_monitoring(self):
        """Stop health monitoring"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        logger.info("Stopped health monitoring")
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.monitoring:
            try:
                for service in self.services.values():
                    result = self._check_service_health(service)
                    self.health_results[service.id] = result
                    
                    # Update service status
                    service.status = result.status
                    service.last_health_check = result.timestamp
                    
                    # Call callbacks
                    for callback in self.callbacks:
                        try:
                            callback(result)
                        except Exception as e:
                            logger.error(f"Health check callback error: {e}")
                
                time.sleep(self.check_interval)
            except Exception as e:
                logger.error(f"Health monitoring error: {e}")
                time.sleep(self.check_interval)
    
    def _check_service_health(self, service: ServiceInstance) -> HealthCheckResult:
        """Check individual service health"""
        start_time = time.time()
        
        try:
            if ASYNC_AVAILABLE:
                # Use async HTTP for better performance
                import asyncio
                result = asyncio.run(self._async_health_check(service))
                return result
            else:
                # Fallback to sync check
                return self._sync_health_check(service)
                
        except Exception as e:
            return HealthCheckResult(
                service_id=service.id,
                status=ServiceStatus.UNHEALTHY,
                response_time=time.time() - start_time,
                timestamp=datetime.now(),
                details={"error": str(e)}
            )
    
    async def _async_health_check(self, service: ServiceInstance) -> HealthCheckResult:
        """Async health check"""
        start_time = time.time()
        
        try:
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                url = f"http://{service.host}:{service.port}{service.health_check_url}"
                
                async with session.get(url) as response:
                    response_time = time.time() - start_time
                    
                    if response.status == 200:
                        status = ServiceStatus.HEALTHY
                    elif response.status < 500:
                        status = ServiceStatus.DEGRADED
                    else:
                        status = ServiceStatus.UNHEALTHY
                    
                    try:
                        response_data = await response.json()
                    except:
                        response_data = await response.text()
                    
                    return HealthCheckResult(
                        service_id=service.id,
                        status=status,
                        response_time=response_time,
                        timestamp=datetime.now(),
                        details={
                            "status_code": response.status,
                            "response": response_data
                        }
                    )
                    
        except Exception as e:
            return HealthCheckResult(
                service_id=service.id,
                status=ServiceStatus.UNHEALTHY,
                response_time=time.time() - start_time,
                timestamp=datetime.now(),
                details={"error": str(e)}
            )
    
    def _sync_health_check(self, service: ServiceInstance) -> HealthCheckResult:
        """Synchronous health check"""
        start_time = time.time()
        
        try:
            import requests
            url = f"http://{service.host}:{service.port}{service.health_check_url}"
            
            response = requests.get(url, timeout=10)
            response_time = time.time() - start_time
            
            if response.status_code == 200:
                status = ServiceStatus.HEALTHY
            elif response.status_code < 500:
                status = ServiceStatus.DEGRADED
            else:
                status = ServiceStatus.UNHEALTHY
            
            try:
                response_data = response.json()
            except:
                response_data = response.text
            
            return HealthCheckResult(
                service_id=service.id,
                status=status,
                response_time=response_time,
                timestamp=datetime.now(),
                details={
                    "status_code": response.status_code,
                    "response": response_data
                }
            )
            
        except Exception as e:
            return HealthCheckResult(
                service_id=service.id,
                status=ServiceStatus.UNHEALTHY,
                response_time=time.time() - start_time,
                timestamp=datetime.now(),
                details={"error": str(e)}
            )


class MessageBroker:
    """Message broker for event-driven architecture"""
    
    def __init__(self, broker_url: str = "localhost"):
        self.broker_url = broker_url
        self.connection = None
        self.channels = {}
        self.subscribers: Dict[str, List[Callable]] = {}
    
    def connect(self):
        """Connect to message broker"""
        if RABBITMQ_AVAILABLE:
            try:
                self.connection = pika.BlockingConnection(
                    pika.ConnectionParameters(self.broker_url)
                )
                logger.info("Connected to RabbitMQ")
                return True
            except Exception as e:
                logger.error(f"Failed to connect to RabbitMQ: {e}")
        
        # Fallback to in-memory broker
        logger.info("Using in-memory message broker")
        return True
    
    def publish(self, topic: str, message: Dict[str, Any]):
        """Publish message to topic"""
        if self.connection and RABBITMQ_AVAILABLE:
            try:
                channel = self.connection.channel()
                channel.queue_declare(queue=topic, durable=True)
                
                channel.basic_publish(
                    exchange='',
                    routing_key=topic,
                    body=json.dumps(message),
                    properties=pika.BasicProperties(delivery_mode=2)  # Persistent
                )
                logger.debug(f"Published message to {topic}")
            except Exception as e:
                logger.error(f"Failed to publish message: {e}")
        else:
            # In-memory delivery
            if topic in self.subscribers:
                for callback in self.subscribers[topic]:
                    try:
                        callback(message)
                    except Exception as e:
                        logger.error(f"Message callback error: {e}")
    
    def subscribe(self, topic: str, callback: Callable[[Dict[str, Any]], None]):
        """Subscribe to topic"""
        if topic not in self.subscribers:
            self.subscribers[topic] = []
        self.subscribers[topic].append(callback)
        
        if self.connection and RABBITMQ_AVAILABLE:
            try:
                channel = self.connection.channel()
                channel.queue_declare(queue=topic, durable=True)
                
                def wrapper(ch, method, properties, body):
                    try:
                        message = json.loads(body.decode())
                        callback(message)
                        ch.basic_ack(delivery_tag=method.delivery_tag)
                    except Exception as e:
                        logger.error(f"Message processing error: {e}")
                        ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
                
                channel.basic_consume(queue=topic, on_message_callback=wrapper)
                logger.info(f"Subscribed to topic: {topic}")
            except Exception as e:
                logger.error(f"Failed to subscribe to topic: {e}")
    
    def close(self):
        """Close connection"""
        if self.connection:
            self.connection.close()


class ServiceMesh:
    """Service mesh management"""
    
    def __init__(self):
        self.services: Dict[str, ServiceInstance] = {}
        self.load_balancer = LoadBalancer()
        self.health_monitor = HealthMonitor()
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}
        self.message_broker = MessageBroker()
        
    def register_service(self, service: ServiceInstance):
        """Register service in mesh"""
        self.services[service.id] = service
        self.load_balancer.add_instance(service)
        self.health_monitor.add_service(service)
        
        # Create circuit breaker for service
        self.circuit_breakers[service.id] = CircuitBreaker(CircuitBreakerConfig())
        
        logger.info(f"Registered service in mesh: {service.name}")
    
    def unregister_service(self, service_id: str):
        """Unregister service from mesh"""
        if service_id in self.services:
            del self.services[service_id]
        
        self.load_balancer.remove_instance(service_id)
        self.health_monitor.remove_service(service_id)
        
        if service_id in self.circuit_breakers:
            del self.circuit_breakers[service_id]
        
        logger.info(f"Unregistered service from mesh: {service_id}")
    
    def call_service(self, service_name: str, endpoint: str, data: Any = None):
        """Call service through mesh"""
        # Find service instance
        service_instances = [
            service for service in self.services.values()
            if service.name == service_name and service.status == ServiceStatus.HEALTHY
        ]
        
        if not service_instances:
            raise Exception(f"No healthy instances of service: {service_name}")
        
        instance = self.load_balancer.get_next_instance()
        if not instance:
            raise Exception(f"Load balancer returned no instance for: {service_name}")
        
        # Use circuit breaker
        circuit_breaker = self.circuit_breakers.get(instance.id)
        if circuit_breaker:
            return circuit_breaker.call(self._make_service_call, instance, endpoint, data)
        else:
            return self._make_service_call(instance, endpoint, data)
    
    def _make_service_call(self, instance: ServiceInstance, endpoint: str, data: Any = None):
        """Make actual service call"""
        try:
            import requests
            url = f"http://{instance.host}:{instance.port}{endpoint}"
            
            self.load_balancer.start_connection(instance.id)
            
            if data:
                response = requests.post(url, json=data, timeout=30)
            else:
                response = requests.get(url, timeout=30)
            
            if response.status_code < 400:
                return response.json() if response.content else None
            else:
                raise Exception(f"Service call failed: {response.status_code}")
                
        except Exception as e:
            raise e
        finally:
            self.load_balancer.end_connection(instance.id)
    
    def start(self):
        """Start service mesh"""
        self.health_monitor.start_monitoring()
        self.message_broker.connect()
        logger.info("Service mesh started")
    
    def stop(self):
        """Stop service mesh"""
        self.health_monitor.stop_monitoring()
        self.message_broker.close()
        logger.info("Service mesh stopped")


class EnterpriseArchitecture:
    """Main enterprise architecture management"""
    
    def __init__(self):
        self.service_mesh = ServiceMesh()
        self.api_gateway_routes: Dict[str, str] = {}
        self.middleware_stack: List[Callable] = []
        
    def setup_microservices_pattern(self):
        """Setup microservices architecture pattern"""
        logger.info("Setting up microservices pattern")
        self.service_mesh.start()
    
    def setup_api_gateway(self, routes: Dict[str, str]):
        """Setup API gateway with routing"""
        self.api_gateway_routes.update(routes)
        logger.info(f"API Gateway configured with {len(routes)} routes")
    
    def add_middleware(self, middleware: Callable):
        """Add middleware to processing stack"""
        self.middleware_stack.append(middleware)
        logger.info("Added middleware to stack")
    
    def process_request(self, path: str, data: Any = None):
        """Process request through architecture"""
        # Apply middleware
        for middleware in self.middleware_stack:
            try:
                data = middleware(data)
            except Exception as e:
                logger.error(f"Middleware error: {e}")
        
        # Route through API gateway
        if path in self.api_gateway_routes:
            service_name = self.api_gateway_routes[path]
            return self.service_mesh.call_service(service_name, path, data)
        else:
            raise Exception(f"No route found for path: {path}")
    
    def get_architecture_metrics(self) -> Dict[str, Any]:
        """Get architecture health metrics"""
        healthy_services = len([
            service for service in self.service_mesh.services.values()
            if service.status == ServiceStatus.HEALTHY
        ])
        
        total_services = len(self.service_mesh.services)
        
        circuit_breaker_states = {}
        for service_id, cb in self.service_mesh.circuit_breakers.items():
            circuit_breaker_states[service_id] = cb.state.value
        
        return {
            "total_services": total_services,
            "healthy_services": healthy_services,
            "service_health_percentage": (healthy_services / total_services * 100) if total_services > 0 else 0,
            "api_gateway_routes": len(self.api_gateway_routes),
            "middleware_count": len(self.middleware_stack),
            "circuit_breaker_states": circuit_breaker_states,
            "timestamp": datetime.now().isoformat()
        }


# Example usage
async def main():
    """Example usage of enterprise architecture"""
    
    # Initialize enterprise architecture
    architecture = EnterpriseArchitecture()
    
    # Setup microservices pattern
    architecture.setup_microservices_pattern()
    
    # Register services
    analysis_service = ServiceInstance(
        id="analysis-1",
        name="analysis-service",
        host="localhost",
        port=8001
    )
    
    reporting_service = ServiceInstance(
        id="reporting-1", 
        name="reporting-service",
        host="localhost",
        port=8002
    )
    
    architecture.service_mesh.register_service(analysis_service)
    architecture.service_mesh.register_service(reporting_service)
    
    # Setup API gateway routes
    architecture.setup_api_gateway({
        "/api/analyze": "analysis-service",
        "/api/reports": "reporting-service"
    })
    
    # Add middleware
    def logging_middleware(data):
        logger.info(f"Processing request with data: {data}")
        return data
    
    architecture.add_middleware(logging_middleware)
    
    # Get metrics
    metrics = architecture.get_architecture_metrics()
    print("Architecture Metrics:", json.dumps(metrics, indent=2))
    
    # Wait a bit then stop
    await asyncio.sleep(5)
    architecture.service_mesh.stop()


if __name__ == "__main__":
    asyncio.run(main())
