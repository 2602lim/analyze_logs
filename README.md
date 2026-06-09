# analyze_logs
一个完整的 Python 脚本，用于解析 Windows 安全/系统/应用程序日志（.evtx 格式），提取关键信息并输出带有可疑项标注的 Excel 报告。
Windows 日志分析与 Excel 报告生成指南
第一步：安装依赖
在终端中运行以下命令安装必要的 Python 库：
pip install python-evtx openpyxl
第二步：导出日志文件（在目标 Win10 电脑上）
1.	打开 事件查看器 (Event Viewer)。
2.	右键点击对应的日志分类，选择 “将所有事件另存为…”。
3.	选择 .evtx 格式进行保存，常见日志文件包括：
◦	安全日志：Security.evtx
◦	系统日志：System.evtx
◦	应用程序日志：Application.evtx
第三步：运行脚本
# 基本用法（将三个日志文件放在同一目录下）
python analyze_logs.py Security.evtx System.evtx Application.evtx

# 自定义输出文件名
python analyze_logs.py *.evtx -o 我的分析报告.xlsx

# 限制解析条数（适用于超大日志文件，提升处理速度）
python analyze_logs.py *.evtx --max 100000
Excel 报告结构说明
生成的 Excel 报告包含以下工作表（Sheet）：
Sheet 名称	内容说明
📊 汇总	总体统计、各类型数量、Top 可疑事件
🚨 可疑事件	所有可疑事件，按威胁等级排序
🔐 Security	安全日志全量（带颜色标注）
⚙️ System	系统日志全量
📋 Application	应用程序日志全量
ℹ️ 说明	等级说明 + 重点事件 ID 含义
可疑等级与颜色对照
颜色	等级	典型场景
🔴	CRITICAL	日志被清除、Defender 检测到恶意软件
🟠	HIGH	暴力破解、账户创建、权限提升、持久化行为
🟡	MEDIUM	可疑进程、防火墙变更、账户操作
🟢	LOW / INFO	一般告警、常规信息记录

