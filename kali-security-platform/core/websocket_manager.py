# WebSocket Real-time Communication System
from fastapi import WebSocket, WebSocketDisconnect
from typing import Dict, List, Set
import json
import asyncio
from datetime import datetime
import uuid

class ConnectionManager:
    """Manage WebSocket connections for real-time updates"""
    
    def __init__(self):
        # Active connections by client ID
        self.active_connections: Dict[str, WebSocket] = {}
        # Subscriptions: scan_id -> set of client_ids
        self.scan_subscriptions: Dict[str, Set[str]] = {}
        # Client info
        self.client_info: Dict[str, Dict] = {}
    
    async def connect(self, websocket: WebSocket, client_id: str = None) -> str:
        """Accept new WebSocket connection"""
        await websocket.accept()
        
        if not client_id:
            client_id = str(uuid.uuid4())
        
        self.active_connections[client_id] = websocket
        self.client_info[client_id] = {
            "connected_at": datetime.utcnow().isoformat(),
            "subscriptions": set()
        }
        
        # Send welcome message
        await self.send_personal_message({
            "type": "connection",
            "status": "connected",
            "client_id": client_id,
            "message": "Connected to Kali Security Platform WebSocket"
        }, client_id)
        
        return client_id
    
    def disconnect(self, client_id: str):
        """Remove WebSocket connection"""
        if client_id in self.active_connections:
            del self.active_connections[client_id]
        
        # Remove from all subscriptions
        for scan_id, subscribers in self.scan_subscriptions.items():
            subscribers.discard(client_id)
        
        if client_id in self.client_info:
            del self.client_info[client_id]
    
    async def send_personal_message(self, message: Dict, client_id: str):
        """Send message to specific client"""
        if client_id in self.active_connections:
            websocket = self.active_connections[client_id]
            await websocket.send_json(message)
    
    async def broadcast(self, message: Dict):
        """Broadcast message to all connected clients"""
        disconnected_clients = []
        
        for client_id, websocket in self.active_connections.items():
            try:
                await websocket.send_json(message)
            except:
                disconnected_clients.append(client_id)
        
        # Clean up disconnected clients
        for client_id in disconnected_clients:
            self.disconnect(client_id)
    
    async def subscribe_to_scan(self, client_id: str, scan_id: str):
        """Subscribe client to scan updates"""
        if scan_id not in self.scan_subscriptions:
            self.scan_subscriptions[scan_id] = set()
        
        self.scan_subscriptions[scan_id].add(client_id)
        
        if client_id in self.client_info:
            self.client_info[client_id]["subscriptions"].add(scan_id)
        
        await self.send_personal_message({
            "type": "subscription",
            "scan_id": scan_id,
            "status": "subscribed",
            "message": f"Subscribed to scan {scan_id}"
        }, client_id)
    
    async def unsubscribe_from_scan(self, client_id: str, scan_id: str):
        """Unsubscribe client from scan updates"""
        if scan_id in self.scan_subscriptions:
            self.scan_subscriptions[scan_id].discard(client_id)
        
        if client_id in self.client_info:
            self.client_info[client_id]["subscriptions"].discard(scan_id)
        
        await self.send_personal_message({
            "type": "subscription",
            "scan_id": scan_id,
            "status": "unsubscribed",
            "message": f"Unsubscribed from scan {scan_id}"
        }, client_id)
    
    async def send_scan_update(self, scan_id: str, update: Dict):
        """Send update to all clients subscribed to a scan"""
        if scan_id in self.scan_subscriptions:
            message = {
                "type": "scan_update",
                "scan_id": scan_id,
                "timestamp": datetime.utcnow().isoformat(),
                **update
            }
            
            disconnected_clients = []
            
            for client_id in self.scan_subscriptions[scan_id]:
                if client_id in self.active_connections:
                    try:
                        await self.send_personal_message(message, client_id)
                    except:
                        disconnected_clients.append(client_id)
            
            # Clean up disconnected clients
            for client_id in disconnected_clients:
                self.disconnect(client_id)
    
    async def send_progress_update(self, scan_id: str, progress: int, status: str = "running"):
        """Send progress update for a scan"""
        await self.send_scan_update(scan_id, {
            "progress": progress,
            "status": status
        })
    
    async def send_output_line(self, scan_id: str, line: str, line_type: str = "stdout"):
        """Send output line from scan"""
        await self.send_scan_update(scan_id, {
            "output": line,
            "output_type": line_type
        })
    
    async def send_scan_complete(self, scan_id: str, result: Dict):
        """Send scan completion notification"""
        await self.send_scan_update(scan_id, {
            "status": "completed",
            "result": result
        })
    
    async def send_scan_error(self, scan_id: str, error: str):
        """Send scan error notification"""
        await self.send_scan_update(scan_id, {
            "status": "error",
            "error": error
        })
    
    def get_connection_stats(self) -> Dict:
        """Get statistics about active connections"""
        return {
            "active_connections": len(self.active_connections),
            "active_scans": len(self.scan_subscriptions),
            "clients": [
                {
                    "client_id": client_id,
                    "connected_at": info.get("connected_at"),
                    "subscriptions": list(info.get("subscriptions", set()))
                }
                for client_id, info in self.client_info.items()
            ]
        }

class ScanStreamManager:
    """Manage real-time scan output streaming"""
    
    def __init__(self, connection_manager: ConnectionManager):
        self.connection_manager = connection_manager
        self.active_streams = {}
    
    async def stream_scan_output(self, scan_id: str, process):
        """Stream scan output in real-time"""
        try:
            # Stream stdout
            async for line in self._read_stream(process.stdout):
                await self.connection_manager.send_output_line(scan_id, line, "stdout")
            
            # Stream stderr
            async for line in self._read_stream(process.stderr):
                await self.connection_manager.send_output_line(scan_id, line, "stderr")
            
            # Wait for process to complete
            return_code = await process.wait()
            
            # Send completion
            await self.connection_manager.send_scan_complete(scan_id, {
                "return_code": return_code
            })
            
        except Exception as e:
            await self.connection_manager.send_scan_error(scan_id, str(e))
    
    async def _read_stream(self, stream):
        """Read from async stream line by line"""
        while True:
            line = await stream.readline()
            if not line:
                break
            yield line.decode().strip()

# Global connection manager
manager = ConnectionManager()
stream_manager = ScanStreamManager(manager)

# WebSocket endpoint handler
async def websocket_endpoint(websocket: WebSocket):
    """Handle WebSocket connections"""
    client_id = await manager.connect(websocket)
    
    try:
        while True:
            # Receive message from client
            data = await websocket.receive_json()
            
            message_type = data.get("type")
            
            if message_type == "subscribe":
                scan_id = data.get("scan_id")
                await manager.subscribe_to_scan(client_id, scan_id)
                
            elif message_type == "unsubscribe":
                scan_id = data.get("scan_id")
                await manager.unsubscribe_from_scan(client_id, scan_id)
                
            elif message_type == "ping":
                await manager.send_personal_message({"type": "pong"}, client_id)
                
            elif message_type == "stats":
                stats = manager.get_connection_stats()
                await manager.send_personal_message({
                    "type": "stats",
                    "data": stats
                }, client_id)
                
    except WebSocketDisconnect:
        manager.disconnect(client_id)
