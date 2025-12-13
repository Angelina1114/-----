"""
TCP 擁塞控制演算法實現
支持多種擁塞控制演算法：Reno、NewReno、Cubic、BBR
"""
from abc import ABC, abstractmethod
from typing import Optional, Tuple
import time
import math


class CongestionAlgorithm(ABC):
    """擁塞控制演算法基類"""
    
    def __init__(self):
        self.congestion_window = 1.0
        self.ssthresh = 16.0
        self.congestion_state = "slow_start"  # slow_start, congestion_avoidance, fast_recovery
    
    @abstractmethod
    def on_ack_received(self, acked_bytes: int = 1) -> Tuple[float, float, str]:
        """
        收到 ACK 時的處理
        返回: (new_cwnd, new_ssthresh, new_state)
        """
        pass
    
    @abstractmethod
    def on_packet_loss(self, loss_type: str = "timeout") -> Tuple[float, float, str]:
        """
        檢測到封包遺失時的處理
        loss_type: "timeout" 或 "fast_retransmit"
        返回: (new_cwnd, new_ssthresh, new_state)
        """
        pass
    
    @abstractmethod
    def on_fast_recovery_exit(self) -> Tuple[float, float, str]:
        """
        退出快速恢復時的處理
        返回: (new_cwnd, new_ssthresh, new_state)
        """
        pass
    
    def reset(self):
        """重置演算法狀態"""
        self.congestion_window = 1.0
        self.ssthresh = 16.0
        self.congestion_state = "slow_start"
        self.initial_ssthresh = 16.0
        self.ssthresh_lowered = False


class RenoAlgorithm(CongestionAlgorithm):
    """TCP Reno 演算法（當前實現）"""
    
    def __init__(self):
        super().__init__()
        self.initial_ssthresh = 16.0  # 記錄初始 ssthresh
        self.ssthresh_lowered = False  # 標記 ssthresh 是否已經降低過
    
    def on_ack_received(self, acked_bytes: int = 1) -> Tuple[float, float, str]:
        # Reno: ssthresh 在收到 ACK 時不會改變，一旦降低就不會再上升
        if self.congestion_state == "slow_start":
            # 慢啟動：每收到一個ACK，擁塞視窗增加1個MSS
            self.congestion_window += 1.0
            if self.congestion_window >= self.ssthresh:
                self.congestion_state = "congestion_avoidance"
        elif self.congestion_state == "congestion_avoidance":
            # 擁塞避免：每收到一個ACK，擁塞視窗增加1/cwnd
            self.congestion_window += 1.0 / self.congestion_window
        # fast_recovery 狀態下收到新 ACK 會退出，由 on_fast_recovery_exit 處理
        # 注意：ssthresh 保持不變，不會因為收到 ACK 而增加
        
        return self.congestion_window, self.ssthresh, self.congestion_state
    
    def on_packet_loss(self, loss_type: str = "timeout") -> Tuple[float, float, str]:
        # Reno: 丟包時降低 ssthresh，一旦降低就不會再上升（即使後續 cwnd 增長）
        if loss_type == "timeout":
            # 超時：進入慢啟動
            new_ssthresh = max(2.0, self.congestion_window / 2.0)
            # 確保 ssthresh 只能降低，不能上升（這是 Reno 的特性）
            if not self.ssthresh_lowered:
                # 第一次降低 ssthresh
                self.ssthresh = new_ssthresh
                self.ssthresh_lowered = True
            else:
                # 已經降低過，只能進一步降低，不能上升
                self.ssthresh = min(self.ssthresh, new_ssthresh)
            self.congestion_window = 1.0
            self.congestion_state = "slow_start"
        elif loss_type == "fast_retransmit":
            # 快速重傳：進入快速恢復
            new_ssthresh = max(2.0, self.congestion_window / 2.0)
            # 確保 ssthresh 只能降低，不能上升
            if not self.ssthresh_lowered:
                # 第一次降低 ssthresh
                self.ssthresh = new_ssthresh
                self.ssthresh_lowered = True
            else:
                # 已經降低過，只能進一步降低，不能上升
                self.ssthresh = min(self.ssthresh, new_ssthresh)
            self.congestion_window = self.ssthresh + 3.0
            self.congestion_state = "fast_recovery"
        
        return self.congestion_window, self.ssthresh, self.congestion_state
    
    def on_fast_recovery_exit(self) -> Tuple[float, float, str]:
        # 退出快速恢復：回到擁塞避免
        self.congestion_window = self.ssthresh
        self.congestion_state = "congestion_avoidance"
        return self.congestion_window, self.ssthresh, self.congestion_state


class NewRenoAlgorithm(CongestionAlgorithm):
    """TCP NewReno 演算法（改進的快速恢復）"""
    
    def __init__(self):
        super().__init__()
        self.recover = 0  # 記錄進入快速恢復時的序列號
    
    def on_ack_received(self, acked_bytes: int = 1, is_partial_ack=False, is_full_ack=False):
        if self.congestion_state == "slow_start":
            self.congestion_window += 1.0
            if self.congestion_window >= self.ssthresh:
                self.congestion_state = "congestion_avoidance"

        elif self.congestion_state == "congestion_avoidance":
            self.congestion_window += 1.0 / self.congestion_window

        elif self.congestion_state == "fast_recovery":

            if is_partial_ack:
                # 部分 ACK ⇒ 不退出 fast recovery
                # 重傳下一個封包
                self.congestion_window += 1.0
                return self.congestion_window, self.ssthresh, "fast_recovery"

            if is_full_ack:
                # 完全 ACK ⇒ 退出 fast recovery
                self.congestion_window = self.ssthresh
                self.congestion_state = "congestion_avoidance"
                return self.congestion_window, self.ssthresh, self.congestion_state

        return self.congestion_window, self.ssthresh, self.congestion_state
        
    def on_packet_loss(self, loss_type: str = "timeout") -> Tuple[float, float, str]:
        if loss_type == "timeout":
            self.ssthresh = max(2.0, self.congestion_window / 2.0)
            self.congestion_window = 1.0
            self.congestion_state = "slow_start"
        elif loss_type == "fast_retransmit":
            # NewReno: 改進的快速恢復
            self.ssthresh = max(2.0, self.congestion_window / 2.0)
            self.congestion_window = self.ssthresh + 3.0
            self.congestion_state = "fast_recovery"
        
        return self.congestion_window, self.ssthresh, self.congestion_state
    
    def on_fast_recovery_exit(self) -> Tuple[float, float, str]:
        self.congestion_window = self.ssthresh
        self.congestion_state = "congestion_avoidance"
        return self.congestion_window, self.ssthresh, self.congestion_state
    
    def reset(self):
        super().reset()
        self.recover = 0


class CubicAlgorithm(CongestionAlgorithm):
    """TCP Cubic 演算法（非線性增長）"""
    
    def __init__(self):
        super().__init__()
        self.c = 0.4  # Cubic 參數
        self.beta = 0.7  # 乘法減半因子
        self.w_max = 0.0  # 進入擁塞避免前的最大 cwnd
        self.k = 0.0  # Cubic 函數的偏移量
        self.epoch_start = 0.0  # 當前擁塞避免階段的開始時間
    
    def _cubic_cwnd(self, t: float) -> float:
        """計算 Cubic 函數的 cwnd 值"""
        if self.w_max <= 0:
            return self.ssthresh
        return self.c * (t - self.k) ** 3 + self.w_max
    
    def _update_k(self):
        """更新 k 值"""
        if self.w_max <= 0:
            self.k = 0
        else:
            self.k = ((self.w_max * (1 - self.beta)) / self.c) ** (1.0 / 3.0)
    
    def on_ack_received(self, acked_bytes: int = 1) -> Tuple[float, float, str]:
        if self.congestion_state == "slow_start":
            self.congestion_window += 1.0
            if self.congestion_window >= self.ssthresh:
                self.congestion_state = "congestion_avoidance"
                self.w_max = self.congestion_window
                self.epoch_start = time.time()
                self._update_k()
        elif self.congestion_state == "congestion_avoidance":
            # Cubic: 使用立方函數增長
            t = time.time() - self.epoch_start
            target = self._cubic_cwnd(t)
            
            # 在目標值附近時，使用更保守的增長
            if self.congestion_window < target:
                # 快速接近目標
                self.congestion_window = min(target, self.congestion_window + (target - self.congestion_window) / self.congestion_window)
            else:
                # 超過目標，緩慢增長
                self.congestion_window += 0.1 / self.congestion_window
        
        return self.congestion_window, self.ssthresh, self.congestion_state
    
    def on_packet_loss(self, loss_type: str = "timeout") -> Tuple[float, float, str]:
        if loss_type == "timeout":
            self.w_max = self.congestion_window
            self.ssthresh = max(2.0, self.congestion_window * self.beta)
            self.congestion_window = 1.0
            self.congestion_state = "slow_start"
        elif loss_type == "fast_retransmit":
            self.w_max = self.congestion_window
            self.ssthresh = max(2.0, self.congestion_window * self.beta)
            self.congestion_window = self.congestion_window * self.beta
            self.congestion_state = "fast_recovery"
            self.epoch_start = time.time()
            self._update_k()
        
        return self.congestion_window, self.ssthresh, self.congestion_state
    
    def on_fast_recovery_exit(self) -> Tuple[float, float, str]:
        self.congestion_state = "congestion_avoidance"
        self.epoch_start = time.time()
        self._update_k()
        return self.congestion_window, self.ssthresh, self.congestion_state
    
    def reset(self):
        super().reset()
        self.w_max = 0.0
        self.k = 0.0
        self.epoch_start = 0.0


class BBRAlgorithm(CongestionAlgorithm):
    """TCP BBR (Bottleneck Bandwidth and Round-trip propagation time) 演算法"""
    
    def __init__(self):
        super().__init__()
        self.bw_estimate = 0.0  # 頻寬估計
        self.rtt_min = float('inf')  # 最小 RTT
        self.pacing_gain = 1.25  # 啟動階段的 pacing gain
        self.cwnd_gain = 2.0  # 啟動階段的 cwnd gain
        self.bbr_state = "STARTUP"  # STARTUP, DRAIN, PROBE_BW, PROBE_RTT
        self.rt_prop = 0.0  # Round-trip propagation time
    
    def on_ack_received(self, acked_bytes: int = 1, rtt: Optional[float] = None) -> Tuple[float, float, str]:
        if rtt is not None:
            # 更新最小 RTT
            if self.rtt_min == float('inf') or rtt < self.rtt_min:
                self.rtt_min = rtt
                self.rt_prop = rtt
        
        if self.bbr_state == "STARTUP":
            # 啟動階段：快速增長
            self.congestion_window += 1.0
            # 如果達到目標（頻寬不再增長），進入 DRAIN
            # 這裡簡化：當 cwnd 達到 ssthresh 時進入 DRAIN
            if self.congestion_window >= self.ssthresh:
                self.bbr_state = "DRAIN"
                self.congestion_state = "congestion_avoidance"
        elif self.bbr_state == "DRAIN":
            # 排空階段：減少到目標值
            if self.congestion_window > self.ssthresh:
                self.congestion_window = max(self.ssthresh, self.congestion_window - 0.5)
            else:
                self.bbr_state = "PROBE_BW"
        elif self.bbr_state == "PROBE_BW":
            # 探測頻寬階段：週期性調整
            # 簡化：緩慢增長
            self.congestion_window += 0.1 / self.congestion_window
            self.congestion_state = "congestion_avoidance"
        elif self.bbr_state == "PROBE_RTT":
            # 探測 RTT 階段：降低 cwnd
            if self.congestion_window > 4:
                self.congestion_window = max(4.0, self.congestion_window - 0.5)
            else:
                self.bbr_state = "PROBE_BW"
        
        return self.congestion_window, self.ssthresh, self.congestion_state
    
    def on_packet_loss(self, loss_type: str = "timeout") -> Tuple[float, float, str]:
        # BBR: 對 loss 不敏感，主要依賴頻寬和 RTT 估計
        if loss_type == "timeout":
            # 超時時才降低
            self.ssthresh = max(2.0, self.congestion_window / 2.0)
            self.congestion_window = max(4.0, self.congestion_window * 0.5)
        elif loss_type == "fast_retransmit":
            # 快速重傳時輕微降低
            self.ssthresh = max(2.0, self.congestion_window * 0.875)
            self.congestion_window = self.congestion_window * 0.875
        
        return self.congestion_window, self.ssthresh, self.congestion_state
    
    def on_fast_recovery_exit(self) -> Tuple[float, float, str]:
        # BBR 不依賴傳統的快速恢復
        self.congestion_state = "congestion_avoidance"
        return self.congestion_window, self.ssthresh, self.congestion_state
    
    def reset(self):
        super().reset()
        self.bw_estimate = 0.0
        self.rtt_min = float('inf')
        self.bbr_state = "STARTUP"
        self.rt_prop = 0.0


def create_algorithm(algorithm_name: str) -> CongestionAlgorithm:
    """創建指定的擁塞控制演算法"""
    algorithms = {
        "Reno": RenoAlgorithm,
        "NewReno": NewRenoAlgorithm,
        "Cubic": CubicAlgorithm,
        "BBR": BBRAlgorithm
    }
    
    if algorithm_name not in algorithms:
        raise ValueError(f"不支持的演算法: {algorithm_name}. 支持的演算法: {list(algorithms.keys())}")
    
    return algorithms[algorithm_name]()

