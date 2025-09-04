import serial
import serial.tools.list_ports
import time
import struct

class STM32DebugParser:
    """STM32数据格式调试和分析工具"""
    
    def __init__(self, port=None, baudrate=1500000):
        self.baudrate = baudrate
        
        # 自动检测串口
        if port is None:
            self.port = self.auto_detect_port()
        else:
            self.port = port
            
        self.connect()
    
    def auto_detect_port(self):
        """自动检测串口"""
        ports = serial.tools.list_ports.comports()
        for port in ports:
            if 'Silicon Labs' in port.description or 'CP210x' in port.description:
                print(f"检测到目标设备: {port.device}")
                return port.device
            if 'STM32' in port.description or 'USB' in port.description:
                print(f"检测到USB设备: {port.device}")
                return port.device
        
        if ports:
            print(f"使用第一个可用端口: {ports[0].device}")
            return ports[0].device
        
        raise Exception("未找到可用串口")
    
    def connect(self):
        """连接串口"""
        try:
            self.ser = serial.Serial(
                port=self.port,
                baudrate=self.baudrate,
                timeout=2
            )
            self.ser.reset_input_buffer()
            print(f"✓ 已连接到 {self.port}")
            return True
        except Exception as e:
            print(f"连接失败: {e}")
            return False
    
    def send_trigger_and_capture(self, duration=2):
        """发送触发命令并捕获原始数据"""
        print(f"\n发送触发命令并捕获 {duration} 秒数据...")
        
        # 发送触发命令
        self.ser.write(b'b')
        print("→ 已发送 'b' 命令")
        
        # 捕获数据
        raw_data = bytearray()
        start_time = time.time()
        
        while (time.time() - start_time) < duration:
            if self.ser.in_waiting > 0:
                data = self.ser.read(self.ser.in_waiting)
                raw_data.extend(data)
                print(f"  接收到 {len(data)} 字节...")
            time.sleep(0.01)
        
        print(f"总共接收: {len(raw_data)} 字节")
        return raw_data
    
    def analyze_packet_patterns(self, data, max_packets=10):
        """分析数据包模式"""
        print(f"\n{'='*60}")
        print("数据包模式分析")
        print(f"{'='*60}")
        
        # 查找0xA0标记
        a0_positions = []
        for i, byte in enumerate(data):
            if byte == 0xA0:
                a0_positions.append(i)
        
        print(f"找到 {len(a0_positions)} 个 0xA0 标记")
        
        if len(a0_positions) < 2:
            print("0xA0 标记太少，无法分析包结构")
            return
        
        # 分析包间距
        intervals = []
        for i in range(len(a0_positions) - 1):
            interval = a0_positions[i+1] - a0_positions[i]
            intervals.append(interval)
        
        # 统计最常见的间距
        from collections import Counter
        interval_counts = Counter(intervals)
        most_common = interval_counts.most_common(3)
        
        print(f"\n数据包间距统计:")
        for interval, count in most_common:
            print(f"  {interval} 字节: {count} 次 ({count/len(intervals)*100:.1f}%)")
        
        # 假设最常见的间距就是包长度
        likely_packet_size = most_common[0][0]
        print(f"\n推测的数据包长度: {likely_packet_size} 字节")
        
        # 分析前几个数据包
        print(f"\n前 {min(max_packets, len(a0_positions)-1)} 个数据包详细分析:")
        print("-" * 60)
        
        for i in range(min(max_packets, len(a0_positions) - 1)):
            start_pos = a0_positions[i]
            end_pos = a0_positions[i + 1]
            packet_data = data[start_pos:end_pos]
            
            print(f"\n数据包 {i+1} (位置: {start_pos}, 长度: {len(packet_data)} 字节):")
            
            # 显示原始十六进制
            hex_str = packet_data.hex().upper()
            print(f"HEX: {' '.join([hex_str[j:j+2] for j in range(0, len(hex_str), 2)])}")
            
            # 尝试不同的解析方式
            self.try_parse_packet(packet_data, i+1)
    
    def try_parse_packet(self, packet_data, packet_num):
        """尝试用不同方式解析数据包"""
        if len(packet_data) < 10:
            print("  数据包太短，无法解析")
            return
        
        print(f"  尝试解析数据包 {packet_num}:")
        
        # 方法1: 假设格式为 [A0][seq_low][seq_high][24字节通道数据][其他][C0]
        if len(packet_data) >= 28:
            try:
                seq1 = struct.unpack('<H', packet_data[1:3])[0]  # 小端序
                seq2 = struct.unpack('>H', packet_data[1:3])[0]  # 大端序
                print(f"    序列号解析1 (小端): {seq1}")
                print(f"    序列号解析2 (大端): {seq2}")
                
                # 解析通道数据 (从位置3开始)
                channels_method1 = []
                for i in range(8):
                    offset = 3 + i * 3
                    if offset + 2 < len(packet_data):
                        bytes_24 = packet_data[offset:offset+3]
                        # 尝试大端序24位
                        val = (bytes_24[0] << 16) | (bytes_24[1] << 8) | bytes_24[2]
                        if val & 0x800000:  # 符号位
                            val = val - 0x1000000
                        channels_method1.append(val)
                print(f"    通道数据 (方法1): {channels_method1[:4]} | {channels_method1[4:8] if len(channels_method1) > 4 else []}")
            except:
                print("    方法1解析失败")
        
        # 方法2: 假设格式为 [A0][24字节通道数据][seq_low][seq_high][其他][C0]
        if len(packet_data) >= 28:
            try:
                # 解析通道数据 (从位置1开始)
                channels_method2 = []
                for i in range(8):
                    offset = 1 + i * 3
                    if offset + 2 < len(packet_data):
                        bytes_24 = packet_data[offset:offset+3]
                        val = (bytes_24[0] << 16) | (bytes_24[1] << 8) | bytes_24[2]
                        if val & 0x800000:
                            val = val - 0x1000000
                        channels_method2.append(val)
                
                # 序列号在通道数据之后
                seq_offset = 1 + 8 * 3  # 25
                if seq_offset + 1 < len(packet_data):
                    seq1 = struct.unpack('<H', packet_data[seq_offset:seq_offset+2])[0]
                    seq2 = struct.unpack('>H', packet_data[seq_offset:seq_offset+2])[0]
                    print(f"    序列号解析1 (小端): {seq1}")
                    print(f"    序列号解析2 (大端): {seq2}")
                
                print(f"    通道数据 (方法2): {channels_method2[:4]} | {channels_method2[4:8] if len(channels_method2) > 4 else []}")
            except:
                print("    方法2解析失败")
        
        # 方法3: 尝试16位数据
        if len(packet_data) >= 20:
            try:
                print(f"    尝试16位数据格式:")
                channels_16bit = []
                for i in range(8):
                    offset = 3 + i * 2  # 假设序列号2字节后是通道数据
                    if offset + 1 < len(packet_data):
                        val = struct.unpack('>H', packet_data[offset:offset+2])[0]
                        channels_16bit.append(val)
                print(f"    16位通道数据: {channels_16bit[:4]} | {channels_16bit[4:8] if len(channels_16bit) > 4 else []}")
            except:
                print("    16位格式解析失败")
        
        # 查找结束标记
        if 0xC0 in packet_data:
            c0_pos = packet_data.find(0xC0)
            print(f"    找到结束标记 0xC0 在位置: {c0_pos}")
        else:
            print(f"    未找到结束标记 0xC0")
    
    def continuous_debug(self, duration=10):
        """连续调试模式"""
        print(f"\n连续调试模式 ({duration} 秒)...")
        print("将显示实时的数据包解析结果")
        print("-" * 60)
        
        buffer = bytearray()
        packet_count = 0
        last_sequence = None
        
        start_time = time.time()
        
        # 发送触发
        self.ser.write(b'b')
        
        while (time.time() - start_time) < duration:
            if self.ser.in_waiting > 0:
                data = self.ser.read(self.ser.in_waiting)
                buffer.extend(data)
                
                # 查找完整数据包
                while len(buffer) >= 10:
                    # 查找起始标记
                    start_idx = buffer.find(0xA0)
                    if start_idx == -1:
                        buffer.clear()
                        break
                    
                    # 移除起始标记之前的数据
                    if start_idx > 0:
                        buffer = buffer[start_idx:]
                    
                    # 查找下一个起始标记来确定包边界
                    next_start = buffer.find(0xA0, 1)
                    if next_start == -1:
                        if len(buffer) > 50:  # 如果缓冲区太大，可能有问题
                            buffer = buffer[1:]
                        break
                    
                    # 提取数据包
                    packet = buffer[:next_start]
                    buffer = buffer[next_start:]
                    
                    packet_count += 1
                    
                    # 简单解析并显示
                    if len(packet) >= 10:
                        print(f"\n[{packet_count}] 包长度: {len(packet)} 字节")
                        
                        # 尝试解析序列号
                        try:
                            if len(packet) >= 3:
                                seq_le = struct.unpack('<H', packet[1:3])[0]
                                seq_be = struct.unpack('>H', packet[1:3])[0]
                                
                                # 判断哪个更像序列号
                                if last_sequence is not None:
                                    diff_le = abs(seq_le - last_sequence)
                                    diff_be = abs(seq_be - last_sequence)
                                    if diff_le < diff_be and diff_le < 10:
                                        seq = seq_le
                                        print(f"序列号: {seq} (小端, +{seq - last_sequence})")
                                    elif diff_be < 10:
                                        seq = seq_be
                                        print(f"序列号: {seq} (大端, +{seq - last_sequence})")
                                    else:
                                        seq = seq_le
                                        print(f"序列号: {seq_le}(LE) / {seq_be}(BE) - 可能有跳跃")
                                else:
                                    seq = seq_le
                                    print(f"序列号: {seq_le}(LE) / {seq_be}(BE)")
                                
                                last_sequence = seq
                        except:
                            print("序列号解析失败")
                        
                        # 显示原始数据
                        hex_preview = packet[:min(16, len(packet))].hex().upper()
                        print(f"数据: {' '.join([hex_preview[i:i+2] for i in range(0, len(hex_preview), 2)])}...")
            
            time.sleep(0.001)
        
        print(f"\n调试完成，共处理 {packet_count} 个数据包")
    
    def suggest_fixes(self):
        """基于分析结果提供修复建议"""
        print(f"\n{'='*60}")
        print("修复建议")
        print(f"{'='*60}")
        print("""
基于你的输出，主要问题是数据包格式解析错误。建议：

1. **重新确认数据包格式**:
   - 你的STM32发送的实际格式可能与代码假设不同
   - 序列号可能是大端序而非小端序
   - 序列号位置可能不在预期位置

2. **检查STM32代码**:
   - 确认数据包的确切格式：[起始][序列号][通道数据][结束]
   - 确认序列号是否为2字节，字节序如何
   - 确认每个通道是否真的是24位(3字节)

3. **调试步骤**:
   - 先运行原始数据分析，确认包结构
   - 修改解析函数以匹配实际格式
   - 逐步验证序列号和通道数据的正确性

4. **可能的格式**:
   根据你的输出，可能的格式是：
   [A0][通道数据16字节][序列号2字节][其他数据][C0]
   或者序列号字节序相反
        """)
    
    def close(self):
        """关闭连接"""
        if hasattr(self, 'ser') and self.ser.is_open:
            self.ser.close()
            print("串口已关闭")

def main():
    print("STM32 数据格式调试器")
    print("="*50)
    
    try:
        debugger = STM32DebugParser()
        
        while True:
            print(f"\n调试选项:")
            print("1. 捕获并分析数据包格式")
            print("2. 连续调试模式")
            print("3. 显示修复建议")
            print("0. 退出")
            
            choice = input("\n选择操作: ").strip()
            
            if choice == '1':
                raw_data = debugger.send_trigger_and_capture(duration=3)
                if raw_data:
                    debugger.analyze_packet_patterns(raw_data)
                input("\n按Enter继续...")
                
            elif choice == '2':
                duration = input("输入调试时长(秒，默认10): ").strip()
                try:
                    duration = int(duration) if duration else 10
                except:
                    duration = 10
                debugger.continuous_debug(duration)
                input("\n按Enter继续...")
                
            elif choice == '3':
                debugger.suggest_fixes()
                input("\n按Enter继续...")
                
            elif choice == '0':
                break
                
    except Exception as e:
        print(f"错误: {e}")
        import traceback
        traceback.print_exc()
    finally:
        if 'debugger' in locals():
            debugger.close()

if __name__ == "__main__":
    main()