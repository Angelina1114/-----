"""
TCP資料包類
模擬TCP資料包的結構和功能
"""
from dataclasses import dataclass
from enum import IntFlag
import time


class TCPFlag(IntFlag):
    """TCP標誌位"""
    SYN = 0x02
    ACK = 0x10
    FIN = 0x01
    RST = 0x04
    PSH = 0x08


@dataclass
class TCPPacket:
    """TCP資料包"""
    source_port: int
    dest_port: int
    seq_num: int
    ack_num: int
    flags: int  # TCP標誌位組合
    window_size: int
    data: bytes = b''
    timestamp: float = 0.0
    
    def __post_init__(self):
        if self.timestamp == 0.0:
            self.timestamp = time.time()
    
    def has_flag(self, flag: TCPFlag) -> bool:
        """檢查是否包含指定標誌位"""
        return (self.flags & flag.value) != 0
    
    def set_flag(self, flag: TCPFlag):
        """設置標誌位"""
        self.flags |= flag.value
    
    def clear_flag(self, flag: TCPFlag):
        """清除標誌位"""
        self.flags &= ~flag.value
    
    def get_size(self) -> int:
        """獲取資料包大小（位元組）"""
        return 20 + len(self.data)  # TCP頭部20位元組 + 資料
    
    def __str__(self) -> str:
        flags_str = []
        if self.has_flag(TCPFlag.SYN):
            flags_str.append("SYN")
        if self.has_flag(TCPFlag.ACK):
            flags_str.append("ACK")
        if self.has_flag(TCPFlag.FIN):
            flags_str.append("FIN")
        if self.has_flag(TCPFlag.RST):
            flags_str.append("RST")
        if self.has_flag(TCPFlag.PSH):
            flags_str.append("PSH")
        
        return (f"TCP[{self.source_port}->{self.dest_port}] "
                f"SEQ={self.seq_num} ACK={self.ack_num} "
                f"FLAGS={','.join(flags_str) if flags_str else 'NONE'} "
                f"WIN={self.window_size} DATA={len(self.data)}B")

