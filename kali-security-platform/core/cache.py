# Cache Manager Module
import json
import pickle
import hashlib
from typing import Any, Optional, Union
from datetime import datetime, timedelta
import redis.asyncio as redis
from functools import wraps
import asyncio

class CacheManager:
    """Redis-based caching with fallback to memory"""
    
    def __init__(self, config):
        self.config = config
        self.redis_client = None
        self.memory_cache = {}  # Fallback memory cache
        self.cache_stats = {
            'hits': 0,
            'misses': 0,
            'errors': 0
        }
        
    async def initialize(self):
        """Initialize Redis connection"""
        try:
            self.redis_client = redis.Redis(
                host=self.config.REDIS_HOST,
                port=self.config.REDIS_PORT,
                db=self.config.REDIS_DB,
                password=self.config.REDIS_PASSWORD,
                decode_responses=False,  # We'll handle encoding/decoding
                socket_connect_timeout=5,
                socket_keepalive=True
            )
            await self.redis_client.ping()
            print("✅ Redis cache initialized")
        except Exception as e:
            print(f"⚠️ Redis connection failed, using memory cache: {e}")
            self.redis_client = None
            
    async def get(self, key: str, default: Any = None) -> Any:
        """Get value from cache"""
        try:
            if self.redis_client:
                value = await self.redis_client.get(self._make_key(key))
                if value:
                    self.cache_stats['hits'] += 1
                    return self._deserialize(value)
            else:
                # Memory cache fallback
                if key in self.memory_cache:
                    entry = self.memory_cache[key]
                    if entry['expires'] > datetime.utcnow():
                        self.cache_stats['hits'] += 1
                        return entry['value']
                    else:
                        del self.memory_cache[key]
                        
            self.cache_stats['misses'] += 1
            return default
            
        except Exception as e:
            self.cache_stats['errors'] += 1
            print(f"Cache get error: {e}")
            return default
            
    async def set(self, key: str, value: Any, ttl: int = None) -> bool:
        """Set value in cache with optional TTL"""
        try:
            ttl = ttl or self.config.CACHE_TTL_DEFAULT
            
            if self.redis_client:
                serialized = self._serialize(value)
                await self.redis_client.setex(
                    self._make_key(key),
                    ttl,
                    serialized
                )
            else:
                # Memory cache fallback
                self.memory_cache[key] = {
                    'value': value,
                    'expires': datetime.utcnow() + timedelta(seconds=ttl)
                }
                
            return True
            
        except Exception as e:
            self.cache_stats['errors'] += 1
            print(f"Cache set error: {e}")
            return False
            
    async def delete(self, key: str) -> bool:
        """Delete value from cache"""
        try:
            if self.redis_client:
                await self.redis_client.delete(self._make_key(key))
            else:
                if key in self.memory_cache:
                    del self.memory_cache[key]
                    
            return True
            
        except Exception as e:
            print(f"Cache delete error: {e}")
            return False
            
    async def exists(self, key: str) -> bool:
        """Check if key exists in cache"""
        try:
            if self.redis_client:
                return await self.redis_client.exists(self._make_key(key)) > 0
            else:
                if key in self.memory_cache:
                    entry = self.memory_cache[key]
                    if entry['expires'] > datetime.utcnow():
                        return True
                    else:
                        del self.memory_cache[key]
                return False
                
        except Exception:
            return False
            
    async def clear_pattern(self, pattern: str) -> int:
        """Clear all keys matching pattern"""
        count = 0
        try:
            if self.redis_client:
                cursor = 0
                while True:
                    cursor, keys = await self.redis_client.scan(
                        cursor,
                        match=f"security:cache:{pattern}*",
                        count=100
                    )
                    if keys:
                        await self.redis_client.delete(*keys)
                        count += len(keys)
                    if cursor == 0:
                        break
            else:
                # Memory cache
                keys_to_delete = [k for k in self.memory_cache if k.startswith(pattern)]
                for key in keys_to_delete:
                    del self.memory_cache[key]
                    count += 1
                    
            return count
            
        except Exception as e:
            print(f"Clear pattern error: {e}")
            return 0
            
    async def get_stats(self) -> dict:
        """Get cache statistics"""
        stats = self.cache_stats.copy()
        
        if self.cache_stats['hits'] + self.cache_stats['misses'] > 0:
            stats['hit_rate'] = (
                self.cache_stats['hits'] / 
                (self.cache_stats['hits'] + self.cache_stats['misses']) * 100
            )
        else:
            stats['hit_rate'] = 0
            
        if self.redis_client:
            try:
                info = await self.redis_client.info('memory')
                stats['memory_used'] = info.get('used_memory_human', 'N/A')
                stats['backend'] = 'redis'
            except:
                stats['backend'] = 'redis (error)'
        else:
            stats['backend'] = 'memory'
            stats['memory_entries'] = len(self.memory_cache)
            
        return stats
        
    def _make_key(self, key: str) -> str:
        """Create namespaced cache key"""
        return f"security:cache:{key}"
        
    def _serialize(self, value: Any) -> bytes:
        """Serialize value for storage"""
        return pickle.dumps(value)
        
    def _deserialize(self, value: bytes) -> Any:
        """Deserialize value from storage"""
        return pickle.loads(value)
        
    async def close(self):
        """Close Redis connection"""
        if self.redis_client:
            await self.redis_client.close()
            
    # Cache decorator
    def cached(self, ttl: int = None, key_prefix: str = None):
        """Decorator for caching function results"""
        def decorator(func):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                # Generate cache key
                cache_key = self._generate_cache_key(
                    func.__name__,
                    args,
                    kwargs,
                    prefix=key_prefix
                )
                
                # Try to get from cache
                cached_value = await self.get(cache_key)
                if cached_value is not None:
                    return cached_value
                    
                # Call function and cache result
                result = await func(*args, **kwargs)
                await self.set(cache_key, result, ttl=ttl)
                
                return result
                
            return wrapper
        return decorator
        
    def _generate_cache_key(self, func_name: str, args: tuple, kwargs: dict, prefix: str = None) -> str:
        """Generate cache key from function call"""
        key_parts = [prefix or func_name]
        
        # Add args to key
        for arg in args:
            if isinstance(arg, (str, int, float, bool)):
                key_parts.append(str(arg))
            else:
                # Hash complex objects
                key_parts.append(hashlib.md5(str(arg).encode()).hexdigest()[:8])
                
        # Add kwargs to key
        for k, v in sorted(kwargs.items()):
            if isinstance(v, (str, int, float, bool)):
                key_parts.append(f"{k}:{v}")
            else:
                key_parts.append(f"{k}:{hashlib.md5(str(v).encode()).hexdigest()[:8]}")
                
        return ":".join(key_parts)


class ScanResultCache(CacheManager):
    """Specialized cache for scan results"""
    
    async def cache_scan_result(self, scan_id: str, module: str, data: dict, ttl: int = None):
        """Cache scan module result"""
        key = f"scan:{scan_id}:{module}"
        ttl = ttl or self.config.CACHE_TTL_SCAN
        await self.set(key, data, ttl)
        
    async def get_scan_result(self, scan_id: str, module: str = None) -> Optional[dict]:
        """Get cached scan result"""
        if module:
            return await self.get(f"scan:{scan_id}:{module}")
        else:
            # Get all modules for scan
            results = {}
            modules = ['network', 'web', 'vuln', 'exploit', 'report']
            for mod in modules:
                data = await self.get(f"scan:{scan_id}:{mod}")
                if data:
                    results[mod] = data
            return results if results else None
            
    async def invalidate_scan(self, scan_id: str):
        """Invalidate all cache for a scan"""
        await self.clear_pattern(f"scan:{scan_id}")


class ReportCache(CacheManager):
    """Specialized cache for reports"""
    
    async def cache_report(self, report_id: str, format: str, content: bytes, ttl: int = None):
        """Cache generated report"""
        key = f"report:{report_id}:{format}"
        ttl = ttl or self.config.CACHE_TTL_REPORT
        await self.set(key, content, ttl)
        
    async def get_report(self, report_id: str, format: str) -> Optional[bytes]:
        """Get cached report"""
        return await self.get(f"report:{report_id}:{format}")