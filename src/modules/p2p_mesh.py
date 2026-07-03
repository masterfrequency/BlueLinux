# By🇭🇷PhonkAlphabet
#!/usr/bin/env python3
"""Module 18: P2P Mesh Intelligence & Federated Learning"""
import json, logging, socket, threading, time
from typing import Dict, List, Any
from datetime import datetime

logger = logging.getLogger('blueteam-p2p')

class P2PMeshModule:
    def __init__(self):
        self.peers = [] # List of (ip, port)
        self.shared_ioc_cache = {}
        self.port = 9443
        self.node_id = f"node_{socket.gethostname()}_{int(time.time())}"
        
        # Start gossip listener thread
        self._stop_event = threading.Event()
        self._listener_thread = threading.Thread(target=self._listen_for_gossip, daemon=True)
        self._listener_thread.start()

    def _listen_for_gossip(self):
        """Listen for incoming IOC gossip messages."""
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            try:
                s.bind(('0.0.0.0', self.port))
                s.settimeout(1.0)
                logger.info(f"P2P Gossip listener started on port {self.port}")
                
                while not self._stop_event.is_set():
                    try:
                        data, addr = s.recvfrom(4096)
                        message = json.loads(data.decode())
                        self._handle_message(message, addr)
                    except socket.timeout:
                        continue
                    except Exception as e:
                        logger.error(f"Gossip listener error: {e}")
            except Exception as e:
                logger.error(f"Could not bind P2P port {self.port}: {e}")

    def _handle_message(self, message: Dict, addr: tuple):
        """Process incoming gossip messages."""
        msg_type = message.get("type")
        if msg_type == "ioc_broadcast":
            ioc_id = message.get("id")
            if ioc_id not in self.shared_ioc_cache:
                logger.info(f"Received new IOC from {addr}: {message.get('value')}")
                self.shared_ioc_cache[ioc_id] = message
                # Re-broadcast to other peers (Gossip)
                self._gossip_rebroadcast(message)
        elif msg_type == "peer_discovery":
            if addr not in self.peers:
                self.peers.append(addr)
                logger.info(f"Discovered new peer: {addr}")

    def broadcast_ioc(self, ioc_type: str, value: str):
        """Initiate a broadcast of a new IOC."""
        ioc_id = f"ioc_{hash(value)}_{int(time.time())}"
        message = {
            "id": ioc_id,
            "type": "ioc_broadcast",
            "ioc_type": ioc_type,
            "value": value,
            "origin": self.node_id,
            "timestamp": datetime.now().isoformat()
        }
        self.shared_ioc_cache[ioc_id] = message
        self._gossip_rebroadcast(message)

    def _gossip_rebroadcast(self, message: Dict):
        """Send message to a subset of known peers."""
        data = json.dumps(message).encode()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            for peer in self.peers:
                try:
                    s.sendto(data, peer)
                except Exception as e:
                    logger.warning(f"Failed to send gossip to {peer}: {e}")

    def get_summary(self) -> Dict:
        return {
            "module": "P2P Mesh Intelligence",
            "node_id": self.node_id,
            "peers_connected": len(self.peers),
            "iocs_shared": len(self.shared_ioc_cache),
            "port": self.port,
            "timestamp": datetime.now().isoformat()
        }

    def __del__(self):
        self._stop_event.set()
        if hasattr(self, '_listener_thread'):
            self._listener_thread.join(timeout=2.0)
