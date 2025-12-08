"""
TCP連接類
實現TCP連接的狀態管理和協議邏輯
"""
from enum import Enum
from typing import Optional, List, Callable
import time
import random
from tcp_packet import TCPPacket, TCPFlag


class TCPState(Enum):
    """TCP連接狀態"""
    CLOSED = "CLOSED"
    LISTEN = "LISTEN"
    SYN_SENT = "SYN_SENT"
    SYN_RECEIVED = "SYN_RECEIVED"
    ESTABLISHED = "ESTABLISHED"
    FIN_WAIT_1 = "FIN_WAIT_1"
    FIN_WAIT_2 = "FIN_WAIT_2"
    CLOSE_WAIT = "CLOSE_WAIT"
    CLOSING = "CLOSING"
    LAST_ACK = "LAST_ACK"
    TIME_WAIT = "TIME_WAIT"


class TCPConnection:
    """TCP連接"""
    
    def __init__(self, local_port: int, remote_port: int, is_server: bool = False):
        self.local_port = local_port
        self.remote_port = remote_port
        self.is_server = is_server
        
        # 序列號和確認號
        self.seq_num = random.randint(1000, 9999) if not is_server else 0
        self.ack_num = 0
        self.remote_seq_num = 0
        self.remote_ack_num = 0
        
        # 狀態
        self.state = TCPState.LISTEN if is_server else TCPState.CLOSED
        
        # 視窗大小
        self.send_window = 65535
        self.receive_window = 65535
        self.congestion_window = 1.0  # 擁塞視窗（MSS），改為浮點數以支持擁塞避免計算
        self.ssthresh = 16.0  # 慢啟動閾值（降低以便更快看到變化）
        
        # 擁塞控制狀態
        self.congestion_state = "slow_start"  # slow_start, congestion_avoidance, fast_recovery
        
        # 資料緩衝區
        self.send_buffer: List[bytes] = []
        self.receive_buffer: List[bytes] = []
        
        # 未確認的資料包（包含發送時間、重傳計數、基準RTO）
        # {'packet': TCPPacket, 'send_time': float, 'retransmit_count': int, 'base_rto': float}
        self.unacked_packets: List[dict] = []
        # 三次握手未確認的控制包（SYN / SYN-ACK）
        self.handshake_unacked: List[dict] = []  # {'packet': TCPPacket, 'send_time': float, 'retransmit_count': int, 'type': str}
        
        # 重傳相關參數
        # 將初始 RTO 調高，避免在正常延遲（例如 0.5s 單程）下誤判超時
        # 三次握手往返時間約為 1.5s，因此預設 RTO 提高到 3s
        self.rto = 3.0  # 重傳超時時間（秒）
        self.handshake_rto = 3.0  # 三次握手初始 RTO
        self.duplicate_ack_count = {}  # {ack_num: count} 用於快速重傳
        self.last_ack_num = 0  # 最後收到的ACK號
        
        # 回調函數
        self.on_state_change: Optional[Callable] = None
        self.on_packet_sent: Optional[Callable] = None
        self.on_packet_received: Optional[Callable] = None
        self.on_metric_change: Optional[Callable] = None  # 新增：數值變化回調
        self.on_retransmit_needed: Optional[Callable] = None  # 新增：需要重傳時的回調
        
        # 統計資訊
        self.stats = {
            'packets_sent': 0,
            'packets_received': 0,
            'bytes_sent': 0,
            'bytes_received': 0,
            'retransmissions': 0,
            'duplicate_acks': 0
        }
    
    def set_state(self, new_state: TCPState):
        """設置連接狀態"""
        if self.state != new_state:
            old_state = self.state
            self.state = new_state
            if self.on_state_change:
                self.on_state_change(old_state, new_state)
            
            # 當連接建立時，記錄初始擁塞控制指標
            if new_state == TCPState.ESTABLISHED and self.on_metric_change:
                self.on_metric_change("cwnd", self.congestion_window, time.time())
                self.on_metric_change("ssthresh", self.ssthresh, time.time())
    
    def send_packet(self, packet: TCPPacket, is_retransmit: bool = False) -> TCPPacket:
        """發送資料包"""
        packet.source_port = self.local_port
        packet.dest_port = self.remote_port
        packet.window_size = self.receive_window
        
        if is_retransmit:
            self.stats['retransmissions'] += 1
        
        self.stats['packets_sent'] += 1
        self.stats['bytes_sent'] += packet.get_size()
        
        if self.on_packet_sent:
            self.on_packet_sent(packet)
        
        return packet
    
    def receive_packet(self, packet: TCPPacket) -> Optional[TCPPacket]:
        """接收資料包"""
        if packet.dest_port != self.local_port:
            return None
        
        self.stats['packets_received'] += 1
        self.stats['bytes_received'] += packet.get_size()
        
        if self.on_packet_received:
            self.on_packet_received(packet)
        
        response = self._process_packet(packet)
        return response
    
    def _process_packet(self, packet: TCPPacket) -> Optional[TCPPacket]:
        """處理接收到的資料包"""
        response = None
        
        # 更新遠程序列號和確認號
        if packet.has_flag(TCPFlag.SYN) or len(packet.data) > 0:
            self.remote_seq_num = packet.seq_num
        if packet.has_flag(TCPFlag.ACK):
            self.remote_ack_num = packet.ack_num
        
        # 狀態機處理
        if self.state == TCPState.LISTEN:
            if packet.has_flag(TCPFlag.SYN):
                # 伺服器收到SYN，發送SYN-ACK
                self.seq_num = random.randint(1000, 9999)
                self.ack_num = packet.seq_num + 1
                self.remote_seq_num = packet.seq_num
                response = self._create_packet(TCPFlag.SYN | TCPFlag.ACK)
                self.set_state(TCPState.SYN_RECEIVED)
                # 記錄握手未確認的 SYN-ACK
                self.handshake_unacked = [{
                    'packet': response,
                    'send_time': time.time(),
                    'retransmit_count': 0,
                    'type': 'syn_ack'
                }]
        
        elif self.state == TCPState.SYN_SENT:
            if packet.has_flag(TCPFlag.SYN) and packet.has_flag(TCPFlag.ACK):
                # 客戶端收到SYN-ACK，發送ACK
                self.ack_num = packet.seq_num + 1
                self.remote_seq_num = packet.seq_num
                response = self._create_packet(TCPFlag.ACK)
                # 收到 SYN-ACK 後，握手確認完成，清除未確認列表
                self.handshake_unacked.clear()
                self.set_state(TCPState.ESTABLISHED)
            elif packet.has_flag(TCPFlag.SYN):
                # 同時打開
                response = self._create_packet(TCPFlag.SYN | TCPFlag.ACK)
                self.set_state(TCPState.SYN_RECEIVED)
        
        elif self.state == TCPState.SYN_RECEIVED:
            if packet.has_flag(TCPFlag.ACK):
                # 收到最終 ACK，握手完成
                self.handshake_unacked.clear()
                self.set_state(TCPState.ESTABLISHED)
        
        elif self.state == TCPState.ESTABLISHED:
            # 處理ACK確認（用於擁塞控制和重傳）- 先處理，因為這可能觸發發送緩衝區中的數據或重傳
            if packet.has_flag(TCPFlag.ACK):
                # 處理所有ACK（包括重複ACK）
                # 注意：即使ACK號碼沒有增加，也要處理（可能是重複ACK）
                ack_response = self.handle_ack(packet.ack_num)
                # handle_ack現在通過回調機制處理快速重傳，不直接返回重傳包
                # 如果返回了包，那是從緩衝區發送的新包
                if ack_response:
                    response = ack_response
            
            if packet.has_flag(TCPFlag.FIN):
                # 收到FIN，進入CLOSE_WAIT
                self.ack_num = packet.seq_num + 1
                response = self._create_packet(TCPFlag.ACK)
                self.set_state(TCPState.CLOSE_WAIT)
            elif len(packet.data) > 0:
                # 接收資料
                self.receive_buffer.append(packet.data)
                self.ack_num = packet.seq_num + len(packet.data)
                # 只有在沒有其他響應時才創建ACK響應
                if not response:
                    response = self._create_packet(TCPFlag.ACK)
        
        elif self.state == TCPState.FIN_WAIT_1:
            if packet.has_flag(TCPFlag.ACK):
                self.set_state(TCPState.FIN_WAIT_2)
            elif packet.has_flag(TCPFlag.FIN):
                self.ack_num = packet.seq_num + 1
                response = self._create_packet(TCPFlag.ACK)
                self.set_state(TCPState.CLOSING)
        
        elif self.state == TCPState.FIN_WAIT_2:
            if packet.has_flag(TCPFlag.FIN):
                self.ack_num = packet.seq_num + 1
                response = self._create_packet(TCPFlag.ACK)
                self.set_state(TCPState.TIME_WAIT)
        
        elif self.state == TCPState.CLOSE_WAIT:
            # 等待應用層關閉
            pass
        
        elif self.state == TCPState.CLOSING:
            if packet.has_flag(TCPFlag.ACK):
                self.set_state(TCPState.TIME_WAIT)
        
        elif self.state == TCPState.LAST_ACK:
            if packet.has_flag(TCPFlag.ACK):
                self.set_state(TCPState.CLOSED)
        
        return response
    
    def _create_packet(self, flags, data: bytes = b'') -> TCPPacket:
        """創建TCP資料包"""
        # 確保flags是整數類型
        flags_int = int(flags) if not isinstance(flags, int) else flags
        packet = TCPPacket(
            source_port=self.local_port,
            dest_port=self.remote_port,
            seq_num=self.seq_num,
            ack_num=self.ack_num,
            flags=flags_int,
            window_size=self.receive_window,
            data=data
        )
        
        # 更新序列號
        if packet.has_flag(TCPFlag.SYN) or packet.has_flag(TCPFlag.FIN):
            self.seq_num += 1
        elif len(data) > 0:
            self.seq_num += len(data)
        
        return packet

    def _packet_end_seq(self, packet: TCPPacket) -> int:
        """計算封包被確認時應超過的序號（含 SYN/FIN 佔用一個序號）"""
        length = len(packet.data)
        if packet.has_flag(TCPFlag.SYN) or packet.has_flag(TCPFlag.FIN):
            length += 1
        return packet.seq_num + length
    
    def connect(self) -> TCPPacket:
        """發起連接（客戶端）"""
        # 允許從 CLOSED 或 SYN_SENT 狀態重新連接（如果之前的連接失敗）
        if self.state not in [TCPState.CLOSED, TCPState.SYN_SENT]:
            raise Exception(f"Cannot connect from state {self.state}")
        
        # 如果已經在 SYN_SENT 狀態，重置為 CLOSED 再連接
        if self.state == TCPState.SYN_SENT:
            self.set_state(TCPState.CLOSED)
        
        self.seq_num = random.randint(1000, 9999)
        packet = self._create_packet(TCPFlag.SYN)
        self.set_state(TCPState.SYN_SENT)
        sent = self.send_packet(packet)
        # 記錄握手未確認的 SYN
        self.handshake_unacked = [{
            'packet': sent,
            'send_time': time.time(),
            'retransmit_count': 0,
            'type': 'syn'
        }]
        return sent
    
    def send_data(self, data: bytes) -> Optional[TCPPacket]:
        """發送資料"""
        if self.state != TCPState.ESTABLISHED:
            return None
        
        # 檢查擁塞視窗
        if len(self.unacked_packets) >= int(self.congestion_window):
            self.send_buffer.append(data)
            return None
        
        packet = self._create_packet(TCPFlag.PSH | TCPFlag.ACK, data)
        # 記錄發送時間和重傳計數
        self.unacked_packets.append({
            'packet': packet,
            'send_time': time.time(),
            'retransmit_count': 0,
            'base_rto': self.rto
        })
        
        # 記錄發送時的擁塞視窗狀態
        if self.on_metric_change:
            self.on_metric_change("cwnd", self.congestion_window, time.time())
            self.on_metric_change("ssthresh", self.ssthresh, time.time())
        
        return self.send_packet(packet)
    
    def close(self) -> Optional[TCPPacket]:
        """關閉連接"""
        if self.state == TCPState.ESTABLISHED:
            packet = self._create_packet(TCPFlag.FIN | TCPFlag.ACK)
            self.set_state(TCPState.FIN_WAIT_1)
            return self.send_packet(packet)
        elif self.state == TCPState.CLOSE_WAIT:
            packet = self._create_packet(TCPFlag.FIN | TCPFlag.ACK)
            self.set_state(TCPState.LAST_ACK)
            return self.send_packet(packet)
        return None
    
    def handle_ack(self, ack_num: int):
        """處理ACK確認"""
        # 檢查是否為重複ACK（用於快速重傳）
        # 注意：重複ACK是指ACK號碼沒有增加，但收到了新的ACK包
        # 只有當last_ack_num已經被設置過（>0）且ACK號碼相同時才是重複ACK
        is_duplicate = (ack_num == self.last_ack_num and 
                       self.last_ack_num > 0 and 
                       len(self.unacked_packets) > 0)
        
        if is_duplicate:
            # 重複ACK
            self.duplicate_ack_count[ack_num] = self.duplicate_ack_count.get(ack_num, 0) + 1
            self.stats['duplicate_acks'] += 1
            
            # 快速重傳：收到3個重複ACK時立即重傳最早的未確認包
            if self.duplicate_ack_count[ack_num] == 3:
                # 找到最早的未確認包（seq_num最小的）
                if self.unacked_packets:
                    # 找到seq_num最小的包
                    earliest_unacked = min(self.unacked_packets, 
                                          key=lambda x: x['packet'].seq_num)
                    packet = earliest_unacked['packet']
                    
                    # 重傳這個包
                    earliest_unacked['retransmit_count'] += 1
                    earliest_unacked['send_time'] = time.time()
                    # 重置重複ACK計數
                    self.duplicate_ack_count[ack_num] = 0
                    # 進入快速恢復狀態
                    self.ssthresh = max(2.0, self.congestion_window / 2.0)
                    self.congestion_window = self.ssthresh + 3.0
                    self.congestion_state = "fast_recovery"
                    
                    if self.on_metric_change:
                        self.on_metric_change("cwnd", self.congestion_window, time.time())
                        self.on_metric_change("ssthresh", self.ssthresh, time.time())
                    
                    # 通過回調通知需要重傳
                    if self.on_retransmit_needed:
                        self.on_retransmit_needed(packet)
                    
                    # 快速重傳後，重複ACK不會確認新數據，所以直接返回
                    # 不繼續處理後續的ACK確認邏輯
                    return None
        else:
            # 新的ACK（ACK號碼增加了），清除重複ACK計數
            if ack_num > self.last_ack_num:
                self.duplicate_ack_count.clear()
                self.last_ack_num = ack_num
            elif self.last_ack_num == 0:
                # 第一次收到ACK，設置last_ack_num
                self.last_ack_num = ack_num
        
        # 移除已確認的資料包
        old_unacked_count = len(self.unacked_packets)
        self.unacked_packets = [p for p in self.unacked_packets
                               if self._packet_end_seq(p['packet']) > ack_num]
        
        # 記錄舊的擁塞視窗值
        old_cwnd = self.congestion_window
        
        # 擁塞控制：每收到一個ACK，擁塞視窗增長
        # 只有在有未確認的資料包被確認時才增長
        if len(self.unacked_packets) < old_unacked_count:
            # 有資料包被確認了
            if self.congestion_state == "slow_start":
                # 慢啟動：每收到一個ACK，擁塞視窗增加1個MSS
                self.congestion_window += 1.0
                if self.congestion_window >= self.ssthresh:
                    self.congestion_state = "congestion_avoidance"
            elif self.congestion_state == "congestion_avoidance":
                # 擁塞避免：每收到一個ACK，擁塞視窗增加1/cwnd
                self.congestion_window += 1.0 / self.congestion_window
            elif self.congestion_state == "fast_recovery":
                # 快速恢復：收到新的ACK，退出快速恢復
                self.congestion_window = self.ssthresh
                self.congestion_state = "congestion_avoidance"
        
        # 記錄當前值（每次ACK都記錄，以便圖表顯示完整過程）
        if self.on_metric_change:
            self.on_metric_change("cwnd", self.congestion_window, time.time())
            self.on_metric_change("ssthresh", self.ssthresh, time.time())
        
        # 發送緩衝區中的資料（可以發送多個，直到達到擁塞視窗限制）
        response_packet = None
        while self.send_buffer and len(self.unacked_packets) < int(self.congestion_window):
            data = self.send_buffer.pop(0)
            packet = self.send_data(data)
            if packet:
                response_packet = packet  # 返回最後一個發送的包
            else:
                break
        
        return response_packet
    
    def check_timeouts(self):
        """檢查超時並重傳"""
        current_time = time.time()
        retransmit_packets = []

        # 1) 處理握手控制封包（SYN / SYN-ACK）
        for unacked in self.handshake_unacked:
            packet = unacked['packet']
            # 指數回退 RTO，最多 60 秒
            timeout = min(60.0, unacked.get('base_rto', self.handshake_rto) * (2 ** unacked['retransmit_count']))
            if current_time - unacked['send_time'] > timeout:
                unacked['retransmit_count'] += 1
                unacked['send_time'] = current_time
                retransmit_packets.append(packet)

        # 2) 處理已建立連線的資料封包
        for unacked in self.unacked_packets:
            packet = unacked['packet']
            timeout = min(60.0, unacked.get('base_rto', self.rto) * (2 ** unacked['retransmit_count']))
            elapsed = current_time - unacked['send_time']
            
            # 如果超過重傳超時時間，需要重傳
            if elapsed > timeout:
                unacked['retransmit_count'] += 1
                unacked['send_time'] = current_time
                
                # 擁塞控制：超時重傳時進入慢啟動（僅在已建立連線下）
                self.ssthresh = max(2.0, self.congestion_window / 2.0)
                self.congestion_window = 1.0
                self.congestion_state = "slow_start"
                
                if self.on_metric_change:
                    self.on_metric_change("cwnd", self.congestion_window, time.time())
                    self.on_metric_change("ssthresh", self.ssthresh, time.time())
                
                retransmit_packets.append(packet)

        return retransmit_packets
    
    def get_stats(self) -> dict:
        """獲取統計資訊"""
        return {
            **self.stats,
            'state': self.state.value,
            'congestion_window': self.congestion_window,
            'send_window': self.send_window,
            'receive_window': self.receive_window
        }