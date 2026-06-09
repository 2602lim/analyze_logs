# analyze_logs
一个完整的 Python 脚本，用于解析 Windows 安全/系统/应用程序日志（.evtx 格式），提取关键信息并输出带有可疑项标注的 Excel 报告。
使用说明
第一步：安装依赖
bashpip install python-evtx openpyxl
第二步：导出日志文件（在目标 Win10 电脑上）
打开事件查看器 → 右键对应日志 → "将所有事件另存为" → 选 .evtx 格式：

安全日志 → Security.evtx
系统日志 → System.evtx
应用程序日志 → Application.evtx

第三步：运行脚本
bash# 基本用法（三个日志放同一目录）
python analyze_logs.py Security.evtx System.evtx Application.evtx

# 自定义输出文件名
python analyze_logs.py *.evtx -o 我的分析报告.xlsx

# 限制解析条数（大日志用）
python analyze_logs.py *.evtx --max 100000

Excel 报告结构
Sheet内容📊 汇总总体统计、各类型数量、Top 可疑事件🚨 可疑事件所有可疑事件，按威胁等级排序🔐 Security安全日志全量（带颜色标注）⚙️ System系统日志全量📋 Application应用程序日志全量ℹ️ 说明等级说明 + 重点事件ID含义
可疑等级颜色

🔴 CRITICAL — 日志被清除、Defender 检测到恶意软件
🟠 HIGH — 暴力破解、账户创建、权限提升、持久化行为
🟡 MEDIUM — 可疑进程、防火墙变更、账户操作
🟢 LOW / INFO — 一般告警
