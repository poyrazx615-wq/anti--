# Rate Limiting Module
import time
import asyncio
from typing import Dict, Optional, Tuple
from collections import defaultdict
from datetime import datetime, timedelta
import redis.asyncio as redis
import json

class RateLimiter:
    """Advanced rate limiting with Redis backend"""
    
    def __init__(self, config):
        self.config = config
        self.redis_client = None
        self.local_cache = defaultdict(list)  # Fallback for Redis failure
        
    async def initialize(self):
        """Initialize Redis connection"""
        try:
            self.redis_client = redis.Redis(
                host=self.config.REDIS_HOST,
                port=self.config.REDIS_PORT,
                db=self.config.REDIS_DB,
                password=self.config.REDIS_PASSWORD,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_keepalive=True,
                socket_keepalive_options={
                    1: 1,  # TCP_KEEPIDLE
                    2: 1,  # TCP_KEEPINTVL  
                    3: 3,  # TCP_KEEPCNT
                }
            )
            await self.redis_client.ping()
        except Exception as e:
            print(f"Redis connection failed, using local cache: {e}")
            self.redis_client = None
            
    async def check_rate_limit(
        self,
        key: str,
        limit: int,
        window: int,
        identifier: str = None
    ) -> Tuple[bool, Dict]:
        """
        Check if request is within rate limit
        
        Args:
            key: Rate limit key (e.g., 'api', 'scan', 'auth')
            limit: Maximum number of requests
            window: Time window in seconds
            identifier: Unique identifier (IP, user_id, etc.)
            
        Returns:
            Tuple of (allowed, info_dict)
        """
        if not self.config.RATE_LIMIT_ENABLED:
            return True, {'limit': limit, 'remaining': limit, 'reset': 0}
            
        # Create full key
        full_key = f"rate_limit:{key}:{identifier or 'global'}"
        
        if self.redis_client:
            return await self._check_redis_rate_limit(full_key, limit, window)
        else:
            return self._check_local_rate_limit(full_key, limit, window)
            
    async def _check_redis_rate_limit(
        self,
        key: str,
        limit: int,
        window: int
    ) -> Tuple[bool, Dict]:
        """Check rate limit using Redis"""
        try:
            pipe = self.redis_client.pipeline()
            now = time.time()
            
            # Remove old entries
            pipe.zremrangebyscore(key, 0, now - window)
            
            # Count current entries
            pipe.zcard(key)
            
            # Get oldest entry
            pipe.zrange(key, 0, 0, withscores=True)
            
            # Add current request
            pipe.zadd(key, {str(now): now})
            
            # Set expiry
            pipe.expire(key, window)
            
            results = await pipe.execute()
            
            current_count = results[1]
            oldest = results[2]
            
            if current_count >= limit:
                # Calculate reset time
                if oldest:
                    reset_time = oldest[0][1] + window
                else:
                    reset_time = now + window
                    
                return False, {
                    'limit': limit,
                    'remaining': 0,
                    'reset': int(reset_time),
                    'retry_after': int(reset_time - now)
                }
                
            return True, {
                'limit': limit,
                'remaining': limit - current_count - 1,
                'reset': int(now + window)
            }
            
        except Exception as e:
            print(f"Redis rate limit error: {e}")
            # Fallback to local
            return self._check_local_rate_limit(key, limit, window)
            
    def _check_local_rate_limit(
        self,
        key: str,
        limit: int,
        window: int
    ) -> Tuple[bool, Dict]:
        """Check rate limit using local cache (fallback)"""
        now = time.time()
        
        # Clean old entries
        self.local_cache[key] = [
            timestamp for timestamp in self.local_cache[key]
            if timestamp > now - window
        ]
        
        current_count = len(self.local_cache[key])
        
        if current_count >= limit:
            # Calculate reset time
            if self.local_cache[key]:
                reset_time = self.local_cache[key][0] + window
            else:
                reset_time = now + window
                
            return False, {
                'limit': limit,
                'remaining': 0,
                'reset': int(reset_time),
                'retry_after': int(reset_time - now)
            }
            
        # Add current request
        self.local_cache[key].append(now)
        
        return True, {
            'limit': limit,
            'remaining': limit - current_count - 1,
            'reset': int(now + window)
        }
        
    async def get_rate_limit_info(self, key: str, identifier: str = None) -> Dict:
        """Get current rate limit information"""
        full_key = f"rate_limit:{key}:{identifier or 'global'}"
        
        # Parse rate limit configuration
        rate_config = getattr(self.config, f'RATE_LIMIT_{key.upper()}', self.config.RATE_LIMIT_DEFAULT)
        limit, period = rate_config.split('/')
        limit = int(limit)
        
        # Convert period to seconds
        period_seconds = self._parse_period(period)
        
        if self.redis_client:
            try:
                now = time.time()
                pipe = self.redis_client.pipeline()
                
                # Remove old entries
                pipe.zremrangebyscore(full_key, 0, now - period_seconds)
                
                # Count current entries
                pipe.zcard(full_key)
                
                results = await pipe.execute()
                current_count = results[1]
                
                return {
                    'limit': limit,
                    'period': period,
                    'used': current_count,
                    'remaining': max(0, limit - current_count),
                    'reset': int(now + period_seconds)
                }
            except:
                pass
                
        # Fallback to local cache
        now = time.time()
        self.local_cache[full_key] = [
            t for t in self.local_cache[full_key]
            if t > now - period_seconds
        ]
        
        current_count = len(self.local_cache[full_key])
        
        return {
            'limit': limit,
            'period': period,
            'used': current_count,
            'remaining': max(0, limit - current_count),
            'reset': int(now + period_seconds)
        }
        
    def _parse_period(self, period: str) -> int:
        """Parse period string to seconds"""
        period = period.lower()
        
        if 'second' in period:
            return int(period.split('second')[0])
        elif 'minute' in period:
            return int(period.split('minute')[0]) * 60
        elif 'hour' in period:
            return int(period.split('hour')[0]) * 3600
        elif 'day' in period:
            return int(period.split('day')[0]) * 86400
        else:
            return 3600  # Default to 1 hour
            
    async def reset_rate_limit(self, key: str, identifier: str = None):
        """Reset rate limit for a specific key"""
        full_key = f"rate_limit:{key}:{identifier or 'global'}"
        
        if self.redis_client:
            try:
                await self.redis_client.delete(full_key)
            except:
                pass
                
        # Also clear local cache
        if full_key in self.local_cache:
            del self.local_cache[full_key]
            
    async def close(self):
        """Close Redis connection"""
        if self.redis_client:
            await self.redis_client.close()


class DistributedRateLimiter(RateLimiter):
    """Distributed rate limiter for multi-instance deployments"""
    
    async def check_global_rate_limit(
        self,
        key: str,
        limit: int,
        window: int
    ) -> Tuple[bool, Dict]:
        """Check global rate limit across all instances"""
        if not self.redis_client:
            return await super().check_rate_limit(key, limit, window, 'global')
            
        global_key = f"global_rate_limit:{key}"
        
        try:
            # Use Redis INCR with expiry for atomic operation
            pipe = self.redis_client.pipeline()
            pipe.incr(global_key)
            pipe.expire(global_key, window)
            
            results = await pipe.execute()
            current_count = results[0]
            
            if current_count > limit:
                ttl = await self.redis_client.ttl(global_key)
                
                return False, {
                    'limit': limit,
                    'remaining': 0,
                    'reset': int(time.time() + ttl),
                    'retry_after': ttl
                }
                
            return True, {
                'limit': limit,
                'remaining': limit - current_count,
                'reset': int(time.time() + window)
            }
            
        except Exception as e:
            print(f"Global rate limit error: {e}")
            return True, {'limit': limit, 'remaining': limit, 'reset': 0}