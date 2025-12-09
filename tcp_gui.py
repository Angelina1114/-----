"""
TCP模擬系統GUI界面
"""
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import time
# 引入 Matplotlib 相關模組
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import matplotlib
# 配置 Matplotlib 支持中文
matplotlib.rcParams['font.sans-serif'] = ['Microsoft YaHei', 'SimHei', 'Arial Unicode MS', 'DejaVu Sans']
matplotlib.rcParams['axes.unicode_minus'] = False  # 解決負號顯示問題

from tcp_simulator import TCPSimulator
from tcp_packet import TCPFlag


class TCPSimulatorGUI:
    """TCP模擬器GUI"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("TCP模擬系統")
        self.root.geometry("1200x800")
        
        self.simulator = TCPSimulator(network_delay=0.5, loss_rate=0.0, bandwidth=1000.0)
        self.simulator.create_connection(client_port=5000, server_port=8000)
        
        self.running = False
        self.update_thread = None
        
        self._create_widgets()
        self._start_update_loop()
    
    def _create_widgets(self):
        """創建界面組件"""
        # 主框架
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 配置網格權重
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(1, weight=1)
        
        # 左側控制面板
        control_frame = ttk.LabelFrame(main_frame, text="控制面板", padding="10")
        control_frame.grid(row=0, column=0, rowspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 10))
        
        # 網路參數
        ttk.Label(control_frame, text="網路參數", font=("Arial", 12, "bold")).grid(
            row=0, column=0, columnspan=2, pady=(0, 10), sticky=tk.W)
        
        ttk.Label(control_frame, text="延遲 (秒):").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.delay_var = tk.DoubleVar(value=0.5)
        ttk.Spinbox(control_frame, from_=0.0, to=5.0, increment=0.1, 
                   textvariable=self.delay_var, width=10).grid(row=1, column=1, pady=5)
        
        ttk.Label(control_frame, text="丟包率 (%):").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.loss_var = tk.DoubleVar(value=0.0)
        ttk.Spinbox(control_frame, from_=0.0, to=100.0, increment=1.0,
                   textvariable=self.loss_var, width=10).grid(row=2, column=1, pady=5)
        
        ttk.Label(control_frame, text="頻寬 (KB/s):").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.bandwidth_var = tk.DoubleVar(value=1000.0)
        ttk.Spinbox(control_frame, from_=100.0, to=10000.0, increment=100.0,
                   textvariable=self.bandwidth_var, width=10).grid(row=3, column=1, pady=5)
        
        ttk.Button(control_frame, text="更新參數", 
                  command=self._update_network_params).grid(
            row=4, column=0, columnspan=2, pady=10, sticky=tk.W+tk.E)
        
        # 分隔線
        ttk.Separator(control_frame, orient=tk.HORIZONTAL).grid(
            row=5, column=0, columnspan=2, sticky=tk.W+tk.E, pady=10)
        
        # 連接控制
        ttk.Label(control_frame, text="連接控制", font=("Arial", 12, "bold")).grid(
            row=6, column=0, columnspan=2, pady=(0, 10), sticky=tk.W)
        
        ttk.Button(control_frame, text="建立連接 (三次握手)",
                  command=self._start_connection).grid(
            row=7, column=0, columnspan=2, pady=5, sticky=tk.W+tk.E)
        
        ttk.Button(control_frame, text="發送資料",
                  command=self._send_data).grid(
            row=8, column=0, columnspan=2, pady=5, sticky=tk.W+tk.E)
        
        ttk.Label(control_frame, text="資料內容:").grid(row=9, column=0, sticky=tk.W, pady=5)
        self.data_entry = ttk.Entry(control_frame, width=15)
        self.data_entry.grid(row=9, column=1, pady=5, sticky=tk.W+tk.E)
        self.data_entry.insert(0, "Hello TCP!")
        
        ttk.Label(control_frame, text="發送數量:").grid(row=10, column=0, sticky=tk.W, pady=5)
        self.packet_count_var = tk.IntVar(value=1)
        ttk.Spinbox(control_frame, from_=1, to=100, increment=1,
                   textvariable=self.packet_count_var, width=10).grid(row=10, column=1, pady=5, sticky=tk.W)
        
        ttk.Button(control_frame, text="關閉連接 (四次揮手)",
                  command=self._close_connection).grid(
            row=11, column=0, columnspan=2, pady=5, sticky=tk.W+tk.E)
        
        ttk.Button(control_frame, text="重置連接",
                  command=self._reset_connection).grid(
            row=12, column=0, columnspan=2, pady=5, sticky=tk.W+tk.E)
        
        # 分隔線
        ttk.Separator(control_frame, orient=tk.HORIZONTAL).grid(
            row=13, column=0, columnspan=2, sticky=tk.W+tk.E, pady=10)
        
        # 狀態資訊
        ttk.Label(control_frame, text="連接狀態", font=("Arial", 12, "bold")).grid(
            row=14, column=0, columnspan=2, pady=(0, 10), sticky=tk.W)
        
        self.client_state_label = ttk.Label(control_frame, text="客戶端: CLOSED")
        self.client_state_label.grid(row=15, column=0, columnspan=2, sticky=tk.W, pady=2)
        
        self.server_state_label = ttk.Label(control_frame, text="伺服器: LISTEN")
        self.server_state_label.grid(row=16, column=0, columnspan=2, sticky=tk.W, pady=2)
        
        # 右側主顯示區
        notebook = ttk.Notebook(main_frame)
        notebook.grid(row=0, column=1, rowspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 資料包日誌標籤頁
        log_frame = ttk.Frame(notebook, padding="10")
        notebook.add(log_frame, text="資料包日誌")
        
        ttk.Label(log_frame, text="資料包傳輸日誌", font=("Arial", 14, "bold")).pack(anchor=tk.W, pady=(0, 10))
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=30, width=80, wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # 統計資訊標籤頁
        stats_frame = ttk.Frame(notebook, padding="10")
        notebook.add(stats_frame, text="統計資訊")
        
        ttk.Label(stats_frame, text="連接統計", font=("Arial", 14, "bold")).pack(anchor=tk.W, pady=(0, 10))
        
        self.stats_text = scrolledtext.ScrolledText(stats_frame, height=30, width=80, wrap=tk.WORD)
        self.stats_text.pack(fill=tk.BOTH, expand=True)
        
        # 狀態圖標籤頁
        state_frame = ttk.Frame(notebook, padding="10")
        notebook.add(state_frame, text="狀態轉換圖")
        
        ttk.Label(state_frame, text="TCP狀態轉換", font=("Arial", 14, "bold")).pack(anchor=tk.W, pady=(0, 10))
        
        self.state_canvas = tk.Canvas(state_frame, bg="white", width=800, height=600)
        self.state_canvas.pack(fill=tk.BOTH, expand=True)
        self._draw_state_diagram()

        # --- 新增：圖表分析標籤頁 ---
        chart_frame = ttk.Frame(notebook, padding="10")
        notebook.add(chart_frame, text="擁塞控制圖表")
        
        ttk.Label(chart_frame, text="擁塞視窗 (CWND) 變化圖", font=("Arial", 14, "bold")).pack(anchor=tk.W, pady=(0, 10))

        self.chart_figure = Figure(figsize=(5, 4), dpi=100)
        self.chart_plot = self.chart_figure.add_subplot(111)
        self.chart_plot.set_title("Congestion Window (CWND) over Time")
        self.chart_plot.set_xlabel("Time (s)")
        self.chart_plot.set_ylabel("Segments (MSS)")
        
        self.chart_canvas = FigureCanvasTkAgg(self.chart_figure, master=chart_frame)
        self.chart_canvas.draw()
        self.chart_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # 添加刷新按鈕
        ttk.Button(chart_frame, text="刷新圖表", command=self._update_charts).pack(pady=5)
    
    def _draw_state_diagram(self):
        """繪製狀態轉換圖"""
        canvas = self.state_canvas
        canvas.delete("all")
        
        # 狀態位置
        states = {
            "CLOSED": (100, 50),
            "LISTEN": (300, 50),
            "SYN_SENT": (500, 150),
            "SYN_RECEIVED": (300, 250),
            "ESTABLISHED": (500, 350),
            "FIN_WAIT_1": (700, 450),
            "FIN_WAIT_2": (700, 550),
            "CLOSE_WAIT": (300, 450),
            "CLOSING": (500, 550),
            "LAST_ACK": (100, 450),
            "TIME_WAIT": (100, 550)
        }
        
        # 繪製狀態框
        for state, (x, y) in states.items():
            canvas.create_rectangle(x-50, y-20, x+50, y+20, outline="black", width=2)
            canvas.create_text(x, y, text=state, font=("Arial", 9))
        
        # 繪製連接線（簡化版）
        connections = [
            ("CLOSED", "LISTEN"),
            ("CLOSED", "SYN_SENT"),
            ("SYN_SENT", "ESTABLISHED"),
            ("LISTEN", "SYN_RECEIVED"),
            ("SYN_RECEIVED", "ESTABLISHED"),
            ("ESTABLISHED", "FIN_WAIT_1"),
            ("FIN_WAIT_1", "FIN_WAIT_2"),
            ("ESTABLISHED", "CLOSE_WAIT"),
            ("CLOSE_WAIT", "LAST_ACK"),
            ("FIN_WAIT_1", "CLOSING"),
            ("CLOSING", "TIME_WAIT"),
            ("FIN_WAIT_2", "TIME_WAIT"),
            ("LAST_ACK", "CLOSED"),
            ("TIME_WAIT", "CLOSED")
        ]
        
        for start, end in connections:
            x1, y1 = states[start]
            x2, y2 = states[end]
            canvas.create_line(x1, y1+20, x2, y2-20, arrow=tk.LAST, fill="gray")
    
    def _update_network_params(self):
        """更新網路參數"""
        self.simulator.network.delay = self.delay_var.get()
        self.simulator.network.loss_rate = self.loss_var.get() / 100.0
        self.simulator.network.bandwidth = self.bandwidth_var.get()
        self._log("網路參數已更新: 延遲={}s, 丟包率={}%, 頻寬={}KB/s".format(
            self.delay_var.get(), self.loss_var.get(), self.bandwidth_var.get()))
    
    def _start_connection(self):
        """開始連接"""
        # 檢查當前狀態，如果已經在連接過程中或已連接，先重置
        if self.simulator.client:
            current_state = self.simulator.client.state.value
            if current_state not in ["CLOSED"]:
                self._log(f"當前狀態為 {current_state}，無法建立新連接。請先重置連接。")
                messagebox.showwarning("警告", f"當前連接狀態為 {current_state}，無法建立新連接。\n請先點擊「重置連接」按鈕。")
                return
        
        self._log("=== 開始TCP三次握手 ===")
        try:
            self.simulator.start_connection()
        except Exception as e:
            self._log(f"建立連接時發生錯誤: {e}")
            messagebox.showerror("錯誤", f"建立連接失敗: {e}\n請先重置連接後再試。")
    
    def _send_data(self):
        """發送資料"""
        data = self.data_entry.get().encode('utf-8')
        if not data:
            messagebox.showwarning("警告", "請輸入要發送的資料")
            return
        
        # 獲取用戶指定的發送數量
        packet_count = self.packet_count_var.get()
        if packet_count < 1:
            messagebox.showwarning("警告", "發送數量必須至少為 1")
            return
        
        self._log(f"=== 發送資料: {data.decode('utf-8')} (數量: {packet_count}) ===")
        
        # 發送指定數量的數據包
        connection = self.simulator.client
        if connection and connection.state.value == "ESTABLISHED":
            # 發送指定數量的數據包，但受擁塞視窗限制
            sent_count = 0
            for i in range(packet_count):
                if len(connection.unacked_packets) < int(connection.congestion_window):
                    self.simulator.send_data(data, from_client=True)
                    sent_count += 1
                else:
                    # 擁塞視窗已滿，將剩餘數據放入緩衝區
                    connection.send_buffer.append(data)
            
            if sent_count < packet_count:
                self._log(f"已發送 {sent_count} 個封包，剩餘 {packet_count - sent_count} 個封包已放入緩衝區")
        else:
            # 連接未建立，只發送一個封包
            if packet_count > 1:
                messagebox.showwarning("警告", "連接未建立，只能發送 1 個封包")
            self.simulator.send_data(data, from_client=True)
    
    def _close_connection(self):
        """關閉連接"""
        self._log("=== 開始TCP四次揮手 ===")
        self.simulator.close_connection(from_client=True)
    
    def _reset_connection(self):
        """重置連接"""
        self.simulator = TCPSimulator(
            network_delay=self.delay_var.get(),
            loss_rate=self.loss_var.get() / 100.0,
            bandwidth=self.bandwidth_var.get()
        )
        self.simulator.create_connection(client_port=5000, server_port=8000)
        self.simulator.client.on_state_change = self._on_state_change
        self.simulator.client.on_packet_sent = self._on_packet_sent
        self.simulator.client.on_packet_received = self._on_packet_received
        self.simulator.server.on_state_change = self._on_state_change
        self.simulator.server.on_packet_sent = self._on_packet_sent
        self.simulator.server.on_packet_received = self._on_packet_received
        self.simulator.network.on_packet_transmitted = self._on_packet_transmitted
        # 注意：on_retransmit_needed 和 on_metric_change 回調已在 create_connection 中設置
        
        self.log_text.delete(1.0, tk.END)
        self._log("連接已重置")
        
        # 清除圖表
        self.chart_plot.clear()
        self.chart_plot.set_title("Congestion Window (CWND) over Time")
        self.chart_plot.set_xlabel("Time (s)")
        self.chart_plot.set_ylabel("Segments (MSS)")
        self.chart_canvas.draw()
    
    def _on_state_change(self, old_state, new_state):
        """狀態改變回調"""
        self._log(f"狀態改變: {old_state.value} -> {new_state.value}")
        self._update_state_labels()
    
    def _on_packet_sent(self, packet):
        """資料包發送回調"""
        source = "客戶端" if packet.source_port == 5000 else "伺服器"
        self._log(f"[發送] {source}: {packet}")
    
    def _on_packet_received(self, packet):
        """資料包接收回調"""
        source = "客戶端" if packet.source_port == 5000 else "伺服器"
        self._log(f"[接收] {source}: {packet}")
    
    def _on_packet_transmitted(self, packet, dest, status):
        """資料包傳輸回調"""
        if status == "LOST":
            self._log(f"[丟失] 資料包在傳輸中丟失: {packet}")
        elif status == "ARRIVED":
            self._log(f"[到達] 資料包已到達目的地")
    
    def _log(self, message: str):
        """添加日誌"""
        timestamp = time.strftime("%H:%M:%S", time.localtime())
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
    
    def _update_state_labels(self):
        """更新狀態標籤"""
        if self.simulator.client:
            self.client_state_label.config(
                text=f"客戶端: {self.simulator.client.state.value}")
        if self.simulator.server:
            self.server_state_label.config(
                text=f"伺服器: {self.simulator.server.state.value}")
    
    def _update_stats(self):
        """更新統計資訊"""
        stats = self.simulator.get_stats()
        self.stats_text.delete(1.0, tk.END)
        
        if 'client' in stats:
            self.stats_text.insert(tk.END, "=== 客戶端統計 ===\n")
            for key, value in stats['client'].items():
                self.stats_text.insert(tk.END, f"{key}: {value}\n")
            self.stats_text.insert(tk.END, "\n")
        
        if 'server' in stats:
            self.stats_text.insert(tk.END, "=== 伺服器統計 ===\n")
            for key, value in stats['server'].items():
                self.stats_text.insert(tk.END, f"{key}: {value}\n")
    
    def _update_charts(self):
        """更新圖表"""
        try:
            history = self.simulator.get_metric_history()
            
            if not history:
                # 如果沒有歷史數據，顯示提示
                self.chart_plot.clear()
                self.chart_plot.text(0.5, 0.5, '暫無數據\n請先建立連接並發送資料', 
                                   ha='center', va='center', transform=self.chart_plot.transAxes,
                                   fontsize=12)
                self.chart_plot.set_title("Congestion Control Analysis")
                self.chart_canvas.draw()
                return

            # 整理數據
            times_cwnd = []
            cwnds = []
            times_ssthresh = []
            ssthreshs = []
            # 事件標記
            event_times = {'loss': [], 'rto': [], 'fast': []}
            event_vals = {'loss': [], 'rto': [], 'fast': []}
            last_cwnd = None
            
            # 找到開始時間以計算相對時間
            start_time = None
            for record in history:
                if record.get('type') in ('METRIC', 'EVENT'):
                    if start_time is None:
                        start_time = record.get('time', 0)
                    break
            
            if start_time is None:
                start_time = time.time()
            
            for record in history:
                if record.get('type') == 'METRIC':
                    record_time = record.get('time', 0)
                    rel_time = record_time - start_time
                    metric = record.get('metric', '')
                    value = record.get('value', 0)
                    
                    if metric == 'cwnd':
                        times_cwnd.append(rel_time)
                        cwnds.append(value)
                        last_cwnd = value
                    elif metric == 'ssthresh':
                        times_ssthresh.append(rel_time)
                        ssthreshs.append(value)
                elif record.get('type') == 'EVENT':
                    record_time = record.get('time', 0)
                    rel_time = record_time - start_time
                    ev = record.get('event')
                    # 事件的Y值用最後一筆 cwnd（若無則用 ssthresh 或 0）
                    y_val = last_cwnd if last_cwnd is not None else (ssthreshs[-1] if ssthreshs else 0)
                    if ev == 'loss':
                        event_times['loss'].append(rel_time)
                        event_vals['loss'].append(y_val)
                    elif ev == 'rto_event' or ev == 'rto':
                        event_times['rto'].append(rel_time)
                        event_vals['rto'].append(y_val)
                    elif ev == 'fast_retx_event' or ev == 'fast':
                        event_times['fast'].append(rel_time)
                        event_vals['fast'].append(y_val)
            
            # 繪圖
            self.chart_plot.clear()
            
            # 只有在有數據時才繪圖
            if times_cwnd and cwnds and len(times_cwnd) > 0:
                # 確保數據點足夠多才能繪製線條
                if len(times_cwnd) == 1:
                    # 只有一個點時，使用散點圖
                    self.chart_plot.scatter(times_cwnd, cwnds, label='CWND', color='blue', s=50, marker='o')
                else:
                    # 多個點時，繪製線條
                    self.chart_plot.plot(times_cwnd, cwnds, label='CWND', color='blue', marker='.', linestyle='-', linewidth=2, markersize=6)
            
            if times_ssthresh and ssthreshs and len(times_ssthresh) > 0:
                if len(times_ssthresh) == 1:
                    self.chart_plot.scatter(times_ssthresh, ssthreshs, label='SSTHRESH', color='red', s=50, marker='s')
                else:
                    self.chart_plot.plot(times_ssthresh, ssthreshs, label='SSTHRESH', color='red', marker='s', linestyle='--', linewidth=2, markersize=6)
            # 事件標記：loss (紅點)、rto (紅叉)、fast retransmit (黃三角)
            if event_times['loss']:
                self.chart_plot.scatter(event_times['loss'], event_vals['loss'], c='red', marker='o', s=60, label='Loss')
            if event_times['rto']:
                self.chart_plot.scatter(event_times['rto'], event_vals['rto'], c='darkred', marker='x', s=80, label='RTO')
            if event_times['fast']:
                self.chart_plot.scatter(event_times['fast'], event_vals['fast'], c='orange', marker='^', s=70, label='Fast RTX')
            
            # 如果沒有任何數據，顯示提示
            if not times_cwnd and not times_ssthresh:
                self.chart_plot.text(0.5, 0.5, '暫無擁塞控制數據\n請先建立連接並發送資料', 
                                   ha='center', va='center', transform=self.chart_plot.transAxes,
                                   fontsize=12)
            
            self.chart_plot.set_title("Congestion Control Analysis")
            self.chart_plot.set_xlabel("Time (s)")
            self.chart_plot.set_ylabel("Window Size (MSS)")
            self.chart_plot.grid(True, alpha=0.3)
            if times_cwnd or times_ssthresh:
                self.chart_plot.legend()
            
            # 自動調整座標軸範圍
            if times_cwnd or times_ssthresh:
                all_times = times_cwnd + times_ssthresh
                all_values = cwnds + ssthreshs
                if all_times and all_values:
                    x_margin = max(0.1, (max(all_times) - min(all_times)) * 0.1) if len(all_times) > 1 else 0.1
                    # 提高縱軸緩衝，避免 CWND 超過 ssthresh 時被截斷
                    value_span = max(all_values) - min(all_values)
                    y_margin = max(
                        1.0,
                        value_span * 0.2,   # 20% 頭尾留白
                        max(all_values) * 0.1  # 最高值再留 10%
                    ) if len(all_values) > 1 else max(1.0, max(all_values) * 0.2)
                    self.chart_plot.set_xlim(min(all_times) - x_margin, max(all_times) + x_margin)
                    self.chart_plot.set_ylim(max(0, min(all_values) - y_margin), max(all_values) + y_margin)
            
            self.chart_canvas.draw()
        except Exception as e:
            # 如果出錯，顯示錯誤信息
            import traceback
            print(f"更新圖表時出錯: {e}")
            traceback.print_exc()
    
    def _start_update_loop(self):
        """啟動更新循環"""
        def update():
            last_chart_update = 0
            while True:
                try:
                    self.simulator.update()
                    self._update_state_labels()
                    self._update_stats()
                    
                    # 每0.5秒自動刷新圖表一次（如果數據有變化）
                    current_time = time.time()
                    if current_time - last_chart_update >= 0.5:
                        # 在主線程中更新圖表
                        self.root.after(0, self._update_charts)
                        last_chart_update = current_time
                    
                    time.sleep(0.1)
                except Exception as e:
                    # 打印錯誤以便調試
                    import traceback
                    traceback.print_exc()
                    pass
        
        self.update_thread = threading.Thread(target=update, daemon=True)
        self.update_thread.start()


def main():
    """主函數"""
    root = tk.Tk()
    app = TCPSimulatorGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()