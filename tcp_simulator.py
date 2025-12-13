"""
TCP模擬器
模擬網路環境和TCP連接
"""
import time
import random
from typing import List, Dict, Optional, Callable
from queue import Queue
from tcp_connection import TCPConnection, TCPState
from tcp_packet import TCPPacket


class NetworkSimulator:
    """網路模擬器"""
    
    def __init__(self, delay: float = 0.1, loss_rate: float = 0.0, 
                 bandwidth: float = 1000.0):
        """
        初始化網路模擬器
        :param delay: 網路延遲（秒）
        :param loss_rate: 丟包率（0.0-1.0）
        :param bandwidth: 頻寬（KB/s）
        """
        self.delay = delay
        self.loss_rate = loss_rate
        self.bandwidth = bandwidth
        self.packet_queue: List[Dict] = []  # {packet, timestamp, dest}
        self.connections: Dict[tuple, TCPConnection] = {}  # (port1, port2) -> connection
        self.on_packet_transmitted: Optional[Callable] = None
    
    def add_connection(self, connection: TCPConnection):
        """添加TCP連接"""
        key = (connection.local_port, connection.remote_port)
        self.connections[key] = connection
    
    def transmit_packet(self, packet: TCPPacket, dest_connection: TCPConnection):
        """傳輸資料包"""
        # 檢查是否丟包
        if random.random() < self.loss_rate:
            if self.on_packet_transmitted:
                self.on_packet_transmitted(packet, None, "LOST")
            return
        
        # 計算傳輸時間（考慮頻寬）
        packet_size_kb = packet.get_size() / 1024.0
        transmission_time = packet_size_kb / self.bandwidth
        
        # 添加到队列
        arrival_time = time.time() + self.delay + transmission_time
        self.packet_queue.append({
            'packet': packet,
            'arrival_time': arrival_time,
            'dest': dest_connection
        })
        
        if self.on_packet_transmitted:
            self.on_packet_transmitted(packet, dest_connection, "TRANSMITTING")
    
    def process_queue(self):
        """處理資料包佇列"""
        current_time = time.time()
        ready_packets = []
        remaining_packets = []
        
        for item in self.packet_queue:
            if current_time >= item['arrival_time']:
                ready_packets.append(item)
            else:
                remaining_packets.append(item)
        
        self.packet_queue = remaining_packets
        
        # 處理就緒的資料包
        for item in ready_packets:
            packet = item['packet']
            dest = item['dest']
            
            if self.on_packet_transmitted:
                self.on_packet_transmitted(packet, dest, "ARRIVED")
            
            # 接收資料包並獲取響應
            response = dest.receive_packet(packet)
            
            if response:
                # 找到發送方連接
                sender_key = (dest.remote_port, dest.local_port)
                sender = self.connections.get(sender_key)
                if sender:
                    self.transmit_packet(response, sender)
    
    def update(self):
        """更新模擬器狀態"""
        self.process_queue()


class TCPSimulator:
    """TCP模擬器主類"""
    
    def __init__(self, network_delay: float = 0.1, loss_rate: float = 0.0,
                 bandwidth: float = 1000.0, congestion_algorithm: str = "Reno"):
        self.network = NetworkSimulator(network_delay, loss_rate, bandwidth)
        self.client: Optional[TCPConnection] = None
        self.server: Optional[TCPConnection] = None
        self.packet_history: List[Dict] = []
        self.metric_history: List[Dict] = [] # 新增：指標歷史數據
        self.running = False
        self.congestion_algorithm = congestion_algorithm
    
    def create_connection(self, client_port: int = 5000, 
                         server_port: int = 8000):
        """創建TCP連接"""
        # 創建客戶端和伺服器連接
        self.client = TCPConnection(client_port, server_port, is_server=False, 
                                    congestion_algorithm=self.congestion_algorithm)
        self.server = TCPConnection(server_port, client_port, is_server=True,
                                    congestion_algorithm=self.congestion_algorithm)
        
        # 設置回調
        self.client.on_state_change = self._on_state_change
        self.client.on_packet_sent = self._on_packet_sent
        self.client.on_packet_received = self._on_packet_received
        self.client.on_metric_change = self._on_metric_change # 新增：綁定指標回調
        self.client.on_retransmit_needed = self._on_retransmit_needed # 新增：重傳回調
        
        self.server.on_state_change = self._on_state_change
        self.server.on_packet_sent = self._on_packet_sent
        self.server.on_packet_received = self._on_packet_received
        self.server.on_retransmit_needed = self._on_retransmit_needed # 新增：重傳回調
        
        # 添加到網路
        self.network.add_connection(self.client)
        self.network.add_connection(self.server)
        
        # 設置網路回調
        self.network.on_packet_transmitted = self._on_packet_transmitted
    
    def _on_state_change(self, old_state: TCPState, new_state: TCPState):
        """狀態改變回調"""
        self.packet_history.append({
            'type': 'STATE_CHANGE',
            'time': time.time(),
            'old_state': old_state.value,
            'new_state': new_state.value
        })
    
    def _on_packet_sent(self, packet: TCPPacket):
        """資料包發送回調"""
        self.packet_history.append({
            'type': 'PACKET_SENT',
            'time': time.time(),
            'packet': packet,
            'source': 'CLIENT' if packet.source_port == self.client.local_port else 'SERVER'
        })
    
    def _on_packet_received(self, packet: TCPPacket):
        """資料包接收回調"""
        self.packet_history.append({
            'type': 'PACKET_RECEIVED',
            'time': time.time(),
            'packet': packet,
            'source': 'CLIENT' if packet.source_port == self.client.local_port else 'SERVER'
        })
    
    def _on_packet_transmitted(self, packet: TCPPacket, dest, status: str):
        """資料包傳輸回調"""
        self.packet_history.append({
            'type': 'PACKET_TRANSMITTED',
            'time': time.time(),
            'packet': packet,
            'status': status
        })
        # 丟包事件記錄到 metric_history，方便圖表標記
        if status == "LOST":
            self.metric_history.append({
                'type': 'EVENT',
                'event': 'loss',
                'seq': packet.seq_num,
                'time': time.time()
            })
        
    def _on_metric_change(self, metric_name: str, value: float, timestamp: float):
        """記錄指標變化"""
        self.metric_history.append({
            'type': 'METRIC',
            'metric': metric_name,
            'value': value,
            'time': timestamp
        })
    
    def _on_retransmit_needed(self, packet: TCPPacket):
        """處理快速重傳需求"""
        # 確定發送方和接收方
        if packet.source_port == self.client.local_port:
            # 客戶端發送的包，重傳給伺服器
            self.network.transmit_packet(packet, self.server)
        else:
            # 伺服器發送的包，重傳給客戶端
            self.network.transmit_packet(packet, self.client)
    
    def start_connection(self):
        """開始連接（三次握手）"""
        if not self.client or not self.server:
            raise Exception("Connection not created")
        
        # 客戶端發送SYN
        syn_packet = self.client.connect()
        self.network.transmit_packet(syn_packet, self.server)
    
    def send_data(self, data: bytes, from_client: bool = True):
        """發送資料"""
        connection = self.client if from_client else self.server
        if not connection:
            return
        
        packet = connection.send_data(data)
        if packet:
            target = self.server if from_client else self.client
            self.network.transmit_packet(packet, target)
    
    def close_connection(self, from_client: bool = True):
        """關閉連接（四次揮手）"""
        connection = self.client if from_client else self.server
        if not connection:
            return
        
        packet = connection.close()
        if packet:
            target = self.server if from_client else self.client
            self.network.transmit_packet(packet, target)
    
    def update(self):
        """更新模擬器"""
        self.network.update()

        def _route_target(item, fallback_client, fallback_server):
            """依據封包/字典決定目的連接"""
            packet = item['packet'] if isinstance(item, dict) else item
            dest_port = item.get('dest') if isinstance(item, dict) else None
            if dest_port is not None:
                if self.server and dest_port == self.server.local_port:
                    return self.server
                if self.client and dest_port == self.client.local_port:
                    return self.client
            # 無 dest 時以封包 source_port 判斷方向
            if self.client and packet.source_port == self.client.local_port:
                return fallback_server
            return fallback_client
        
        # 檢查超時並處理重傳
        if self.client:
            retransmit_packets = self.client.check_timeouts()
            for item in retransmit_packets:
                packet = item['packet'] if isinstance(item, dict) else item
                target = _route_target(item, self.client, self.server)
                if target:
                    self.network.transmit_packet(packet, target)
            # pacing 依 cwnd 發送緩衝資料
            paced_list = self.client.drain_send_buffer()
            for p in paced_list:
                self.network.transmit_packet(p, self.server)
        
        if self.server:
            retransmit_packets = self.server.check_timeouts()
            for item in retransmit_packets:
                packet = item['packet'] if isinstance(item, dict) else item
                target = _route_target(item, self.server, self.client)
                if target:
                    self.network.transmit_packet(packet, target)
            paced_list = self.server.drain_send_buffer()
            for p in paced_list:
                self.network.transmit_packet(p, self.client)
    
    def get_history(self) -> List[Dict]:
        """獲取歷史記錄"""
        return self.packet_history
    
    def get_metric_history(self) -> List[Dict]:
        """獲取指標歷史記錄"""
        return self.metric_history
    
    def get_stats(self) -> Dict:
        """獲取統計資訊"""
        stats = {}
        if self.client:
            stats['client'] = self.client.get_stats()
        if self.server:
            stats['server'] = self.server.get_stats()
        return stats