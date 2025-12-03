# main.py
"""
迷你Wireshark - 主程序入口
"""
import tkinter as tk
from gui import PacketAnalyzerGUI

if __name__ == "__main__":
    print("=" * 60)
    print("迷你Wireshark - 网络抓包分析工具")
    print("版本: 1.0")
    print("功能: 实时抓包、协议解析、数据分析")
    print("=" * 60)
    print("注意：请点击'开始抓包'按钮开始捕获数据包")
    print("=" * 60)
    
    try:
        # 启动GUI
        root = tk.Tk()
        app = PacketAnalyzerGUI(root)
        root.mainloop()
        
    except KeyboardInterrupt:
        print("\n程序被用户中断")
    except Exception as e:
        print(f"\n程序错误: {e}")
        input("按Enter退出...")