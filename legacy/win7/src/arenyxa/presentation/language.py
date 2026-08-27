from __future__ import annotations

import re
from collections.abc import Iterable

from arenyxa.qt_compat.QtCore import QEvent, QObject, QLocale, QTimer, Qt, Signal
from arenyxa.qt_compat.QtWidgets import QApplication, QAbstractButton, QComboBox, QGroupBox, QLabel, QLineEdit, QPlainTextEdit, QTabWidget, QTableWidget, QWidget

from arenyxa.presentation.i18n_catalog import NATIVE_PHRASES

SYSTEM_LOCALE = "system"
LOCALES = {
    SYSTEM_LOCALE: "跟随系统 / Follow system",
    "zh_CN": "简体中文",
    "zh_TW": "繁體中文",
    "en_US": "English",
    "fr_FR": "Français",
    "ru_RU": "Русский",
    "de_DE": "Deutsch",
    "ja_JP": "日本語",
    "ko_KR": "한국어",
    "ar_SA": "العربية",
    "la_VA": "Latina",
}

                                                                                     
                                                                                    
                      
EN = {
    "nav.dashboard": "Dashboard", "nav.tasks": "Capture Tasks", "nav.capture": "Capture", "nav.search": "Search Center",
    "nav.data": "Data Management", "nav.network": "Network Analysis", "nav.proxy": "Proxy", "nav.mitm_proxy": "MITM Workbench", "nav.professional": "Professional Suite", "nav.workflow": "Workflows",
    "nav.automation": "Automation", "nav.recovery": "Recovery & Health", "nav.advanced": "Advanced Platform", "nav.studio": "Intelligence Studio", "nav.visualization": "Visualization Studio",
    "nav.version": "Data Versions", "nav.plugins": "Plugins", "nav.console": "Terminal Console",
    "nav.logs": "Logs & Diagnostics", "nav.enterprise": "Enterprise Administration", "nav.personalization": "Personalization", "nav.settings": "Settings", "nav.about": "About",
    "top.search": "Search tasks, data, or commands…", "top.run": "Start Capture", "top.pause": "Pause",
    "top.stop": "Stop", "top.open_data": "Open Data Folder", "top.capture": "Network Capture",
    "status.ready": "Ready", "language.system": "Follow system", "language.interface": "Interface language",
    "inspector.title": "Context Inspector", "inspector.empty": "Select a task, run, request, or data record to inspect its context.",
    "service.local": "Local service", "settings.language": "Language, RTL & advanced settings",
    "nav.group.advanced": "Advanced", "nav.group.developer": "Developer",
    "nav.dev.api": "API Explorer", "nav.dev.sandbox": "Plugin Sandbox", "nav.dev.performance": "Performance Monitor",
    "action.diagnostics": "Run Diagnostics", "action.repair": "Repair Center",
}
ZH_CN = {
    **EN,
    "nav.dashboard": "仪表盘", "nav.tasks": "抓取任务", "nav.capture": "捕获", "nav.search": "搜索中心", "nav.data": "数据管理",
    "nav.network": "网络分析", "nav.proxy": "代理工作台", "nav.mitm_proxy": "MITM 工作台", "nav.professional": "专业工具中心", "nav.workflow": "工作流", "nav.automation": "自动化计划", "nav.recovery": "运行恢复", "nav.advanced": "高级平台", "nav.studio": "智能工作台",
    "nav.visualization": "可视化中心", "nav.version": "数据版本", "nav.plugins": "插件系统", "nav.console": "终端控制台",
    "nav.logs": "日志与诊断", "nav.enterprise": "企业管理", "nav.personalization": "个性化", "nav.settings": "设置", "nav.about": "关于", "top.search": "搜索任务、数据或命令…",
    "top.run": "开始抓取", "top.pause": "暂停", "top.stop": "停止", "top.open_data": "打开数据文件夹",
    "top.capture": "网络捕获", "status.ready": "就绪", "language.system": "跟随系统", "language.interface": "界面语言",
    "inspector.title": "上下文检查器", "inspector.empty": "选择任务、运行、请求或数据记录以查看上下文。",
    "service.local": "本地服务", "settings.language": "语言、RTL 与高级设置",
    "nav.group.advanced": "高级", "nav.group.developer": "开发者",
    "nav.dev.api": "API Explorer", "nav.dev.sandbox": "插件沙箱", "nav.dev.performance": "性能监视器",
    "action.diagnostics": "运行诊断", "action.repair": "Repair Center",
}

NATIVE_OVERRIDES = {
    "zh_TW": {**EN, "nav.dashboard":"儀表板","nav.tasks":"擷取任務","nav.search":"搜尋中心","nav.data":"資料管理","nav.network":"網路分析","nav.workflow":"工作流程","nav.automation":"自動化排程","nav.recovery":"執行恢復","nav.advanced":"進階平台","nav.studio":"智慧工作台","nav.visualization":"視覺化中心","nav.version":"資料版本","nav.plugins":"外掛系統","nav.console":"終端控制台","nav.logs":"日誌與診斷","nav.personalization":"個人化","nav.settings":"設定","nav.about":"關於","top.search":"搜尋任務、資料或命令…","top.run":"開始擷取","top.pause":"暫停","top.stop":"停止","top.open_data":"開啟資料資料夾","top.capture":"網路擷取","status.ready":"就緒","language.system":"跟隨系統","language.interface":"介面語言","inspector.title":"內容檢查器","service.local":"本機服務"},
    "fr_FR": {**EN, "nav.dashboard":"Tableau de bord","nav.tasks":"Tâches de collecte","nav.search":"Centre de recherche","nav.data":"Gestion des données","nav.network":"Analyse réseau","nav.workflow":"Flux de travail","nav.automation":"Automatisation","nav.recovery":"Récupération","nav.advanced":"Plateforme avancée","nav.studio":"Studio intelligent","nav.visualization":"Studio de visualisation","nav.version":"Versions des données","nav.plugins":"Extensions","nav.console":"Console terminal","nav.logs":"Journaux et diagnostics","nav.personalization":"Personnalisation","nav.settings":"Paramètres","nav.about":"À propos","top.search":"Rechercher tâches, données ou commandes…","top.run":"Démarrer la collecte","top.pause":"Pause","top.stop":"Arrêter","top.open_data":"Ouvrir le dossier de données","top.capture":"Capture réseau","status.ready":"Prêt","language.system":"Suivre le système","language.interface":"Langue de l’interface","inspector.title":"Inspecteur de contexte","service.local":"Service local"},
    "ru_RU": {**EN, "nav.dashboard":"Панель","nav.tasks":"Задачи сбора","nav.search":"Поиск","nav.data":"Управление данными","nav.network":"Анализ сети","nav.workflow":"Процессы","nav.automation":"Автоматизация","nav.recovery":"Восстановление","nav.advanced":"Расширенная платформа","nav.studio":"Интеллектуальная студия","nav.visualization":"Визуализация","nav.version":"Версии данных","nav.plugins":"Плагины","nav.console":"Терминал","nav.logs":"Журналы и диагностика","nav.personalization":"Персонализация","nav.settings":"Настройки","nav.about":"О программе","top.search":"Поиск задач, данных или команд…","top.run":"Начать сбор","top.pause":"Пауза","top.stop":"Стоп","top.open_data":"Открыть папку данных","top.capture":"Сетевой захват","status.ready":"Готово","language.system":"Как в системе","language.interface":"Язык интерфейса","inspector.title":"Инспектор контекста","service.local":"Локальный сервис"},
    "de_DE": {**EN, "nav.dashboard":"Übersicht","nav.tasks":"Erfassungsaufgaben","nav.search":"Suche","nav.data":"Datenverwaltung","nav.network":"Netzwerkanalyse","nav.workflow":"Workflows","nav.automation":"Automatisierung","nav.recovery":"Wiederherstellung","nav.advanced":"Erweiterte Plattform","nav.studio":"Intelligence Studio","nav.visualization":"Visualisierung","nav.version":"Datenversionen","nav.plugins":"Plugins","nav.console":"Terminal-Konsole","nav.logs":"Protokolle & Diagnose","nav.personalization":"Personalisierung","nav.settings":"Einstellungen","nav.about":"Über","top.search":"Aufgaben, Daten oder Befehle suchen…","top.run":"Erfassung starten","top.pause":"Pause","top.stop":"Stopp","top.open_data":"Datenordner öffnen","top.capture":"Netzwerkerfassung","status.ready":"Bereit","language.system":"Systemsprache folgen","language.interface":"Oberflächensprache","inspector.title":"Kontextinspektor","service.local":"Lokaler Dienst"},
    "ja_JP": {**EN, "nav.dashboard":"ダッシュボード","nav.tasks":"取得タスク","nav.search":"検索センター","nav.data":"データ管理","nav.network":"ネットワーク分析","nav.workflow":"ワークフロー","nav.automation":"自動化","nav.recovery":"実行復旧","nav.advanced":"高度なプラットフォーム","nav.studio":"インテリジェンススタジオ","nav.visualization":"可視化スタジオ","nav.version":"データ版","nav.plugins":"プラグイン","nav.console":"ターミナル","nav.logs":"ログと診断","nav.personalization":"パーソナライズ","nav.settings":"設定","nav.about":"このアプリについて","top.search":"タスク、データ、コマンドを検索…","top.run":"取得開始","top.pause":"一時停止","top.stop":"停止","top.open_data":"データフォルダーを開く","top.capture":"ネットワーク取得","status.ready":"準備完了","language.system":"システムに従う","language.interface":"表示言語","inspector.title":"コンテキストインスペクター","service.local":"ローカルサービス"},
    "ko_KR": {**EN, "nav.dashboard":"대시보드","nav.tasks":"수집 작업","nav.search":"검색 센터","nav.data":"데이터 관리","nav.network":"네트워크 분석","nav.workflow":"워크플로","nav.automation":"자동화","nav.recovery":"실행 복구","nav.advanced":"고급 플랫폼","nav.studio":"인텔리전스 스튜디오","nav.visualization":"시각화 스튜디오","nav.version":"데이터 버전","nav.plugins":"플러그인","nav.console":"터미널 콘솔","nav.logs":"로그 및 진단","nav.personalization":"개인 설정","nav.settings":"설정","nav.about":"정보","top.search":"작업, 데이터 또는 명령 검색…","top.run":"수집 시작","top.pause":"일시 중지","top.stop":"중지","top.open_data":"데이터 폴더 열기","top.capture":"네트워크 캡처","status.ready":"준비됨","language.system":"시스템 설정 따름","language.interface":"인터페이스 언어","inspector.title":"컨텍스트 검사기","service.local":"로컬 서비스"},
    "ar_SA": {**EN, "nav.dashboard":"لوحة المعلومات","nav.tasks":"مهام الالتقاط","nav.search":"مركز البحث","nav.data":"إدارة البيانات","nav.network":"تحليل الشبكة","nav.workflow":"سير العمل","nav.automation":"الأتمتة","nav.recovery":"استعادة التشغيل","nav.advanced":"المنصة المتقدمة","nav.studio":"استوديو الذكاء","nav.visualization":"استوديو التصور","nav.version":"إصدارات البيانات","nav.plugins":"الإضافات","nav.console":"وحدة الطرفية","nav.logs":"السجلات والتشخيص","nav.personalization":"التخصيص","nav.settings":"الإعدادات","nav.about":"حول","top.search":"ابحث في المهام أو البيانات أو الأوامر…","top.run":"بدء الالتقاط","top.pause":"إيقاف مؤقت","top.stop":"إيقاف","top.open_data":"فتح مجلد البيانات","top.capture":"التقاط الشبكة","status.ready":"جاهز","language.system":"اتباع النظام","language.interface":"لغة الواجهة","inspector.title":"فاحص السياق","service.local":"الخدمة المحلية"},
    "la_VA": {**EN, "nav.dashboard":"Tabula","nav.tasks":"Munera collectionis","nav.search":"Centrum quaestionis","nav.data":"Administratio datorum","nav.network":"Analysis retis","nav.workflow":"Fluxus operis","nav.automation":"Automatio","nav.recovery":"Recuperatio","nav.advanced":"Instrumenta provecta","nav.studio":"Officina intelligentiae","nav.visualization":"Visualizatio","nav.version":"Versiones datorum","nav.plugins":"Additamenta","nav.console":"Consola terminalis","nav.logs":"Acta et diagnostica","nav.personalization":"Personalizatio","nav.settings":"Configurationes","nav.about":"De Arenyxa","top.search":"Quaere munera, data vel mandata…","top.run":"Incipe collectionem","top.pause":"Pausa","top.stop":"Siste","top.open_data":"Aperi folder datorum","top.capture":"Captura retis","status.ready":"Paratum","language.system":"Sequere systema","language.interface":"Lingua interfaciei","inspector.title":"Inspector contextus","service.local":"Servitium locale"},
}
EXTRA_NAV_NATIVE = {
    "zh_TW": {"nav.capture": "擷取", "nav.group.advanced": "進階", "nav.group.developer": "開發者", "action.diagnostics": "執行診斷", "action.repair": "修復中心", "nav.dev.api": "API 瀏覽器", "nav.dev.sandbox": "外掛沙箱", "nav.dev.performance": "效能監視器"},
    "fr_FR": {"nav.capture": "Capture", "nav.group.advanced": "Avancé", "nav.group.developer": "Développeur", "action.diagnostics": "Lancer le diagnostic", "action.repair": "Centre de réparation", "nav.dev.api": "Explorateur API", "nav.dev.sandbox": "Bac à sable des extensions", "nav.dev.performance": "Moniteur de performances"},
    "ru_RU": {"nav.capture": "Захват", "nav.group.advanced": "Расширенные", "nav.group.developer": "Разработчик", "action.diagnostics": "Запустить диагностику", "action.repair": "Центр восстановления", "nav.dev.api": "API Explorer", "nav.dev.sandbox": "Песочница плагинов", "nav.dev.performance": "Монитор производительности"},
    "de_DE": {"nav.capture": "Erfassung", "nav.group.advanced": "Erweitert", "nav.group.developer": "Entwickler", "action.diagnostics": "Diagnose ausführen", "action.repair": "Reparaturzentrum", "nav.dev.api": "API-Explorer", "nav.dev.sandbox": "Plugin-Sandbox", "nav.dev.performance": "Leistungsmonitor"},
    "ja_JP": {"nav.capture": "取得", "nav.group.advanced": "高度", "nav.group.developer": "開発者", "action.diagnostics": "診断を実行", "action.repair": "修復センター", "nav.dev.api": "API エクスプローラー", "nav.dev.sandbox": "プラグインサンドボックス", "nav.dev.performance": "パフォーマンスモニター"},
    "ko_KR": {"nav.capture": "캡처", "nav.group.advanced": "고급", "nav.group.developer": "개발자", "action.diagnostics": "진단 실행", "action.repair": "복구 센터", "nav.dev.api": "API 탐색기", "nav.dev.sandbox": "플러그인 샌드박스", "nav.dev.performance": "성능 모니터"},
    "ar_SA": {"nav.capture": "الالتقاط", "nav.group.advanced": "متقدم", "nav.group.developer": "المطور", "action.diagnostics": "تشغيل التشخيص", "action.repair": "مركز الإصلاح", "nav.dev.api": "مستكشف API", "nav.dev.sandbox": "صندوق عزل الإضافات", "nav.dev.performance": "مراقب الأداء"},
    "la_VA": {"nav.capture": "Captura", "nav.group.advanced": "Provecta", "nav.group.developer": "Developer", "action.diagnostics": "Exsequere diagnostica", "action.repair": "Centrum reparationis", "nav.dev.api": "Explorator API", "nav.dev.sandbox": "Sandbox additamentorum", "nav.dev.performance": "Monitor efficientiae"},
}
for _locale, _extra in EXTRA_NAV_NATIVE.items():
    NATIVE_OVERRIDES.setdefault(_locale, {**EN}).update(_extra)

TRANSLATIONS = {"zh_CN": ZH_CN, **NATIVE_OVERRIDES, "en_US": EN}

                                                                                   
                                                                                                  
PHRASES = {
    "仪表盘":"Dashboard", "概览您的本地网页索引与系统状态":"Overview of your local web index and system status",
    "抓取任务":"Capture Tasks", "搜索中心":"Search Center", "数据管理":"Data Management", "网络分析":"Network Analysis",
    "工作流":"Workflows", "自动化计划":"Automation", "高级平台":"Advanced Platform", "可视化中心":"Visualization Studio",
    "数据版本控制":"Data Version Control", "数据版本":"Data Versions", "插件与沙箱":"Plugins & Sandbox", "插件系统":"Plugins",
    "终端控制台":"Terminal Console", "日志与诊断":"Logs & Diagnostics", "个性化与设置":"Personalization & Settings", "个性化":"Personalization",
    "关于 Arenyxa":"About Arenyxa", "上下文检查器":"Context Inspector", "界面语言":"Interface language", "跟随系统":"Follow system",
    "开始抓取":"Start Capture", "开始捕获":"Start Capture", "网络捕获":"Network Capture", "暂停":"Pause", "停止":"Stop", "恢复":"Resume",
    "打开搜索页面":"Open Search Page", "打开数据文件夹":"Open Data Folder", "刷新":"Refresh", "新建任务":"New Task", "新建计划":"New Schedule",
    "新建采集任务":"New Capture Task", "编辑采集任务":"Edit Capture Task", "任务列表":"Task List", "任务名称":"Task name", "目标 URL":"Target URL",
    "解析类型":"Parser type", "字段抽取":"Field extraction", "添加字段":"Add field", "删除字段":"Remove field", "字段":"Field", "名称":"Name",
    "选择器":"Selector", "类型":"Type", "规则":"Rule", "必填":"Required", "多值":"Multiple values", "保存工作流":"Save Workflow",
    "执行":"Run", "运行":"Run", "执行结果":"Execution result", "运行分析":"Run analysis", "测试连接与能力":"Test connection & capabilities",
    "搜索":"Search", "搜索结果":"Search results", "搜索名称、标签或 URL":"Search name, tag, or URL", "输入关键词；不向网络发送搜索内容":"Enter keywords; search content never leaves the device",
    "导出":"Export", "导出结果":"Export Results", "导出图表":"Export Chart", "导出 PNG":"Export PNG", "预览":"Preview", "比较":"Compare",
    "创建 Revision":"Create Revision", "比较所选两个 Revision":"Compare selected revisions", "数据集":"Dataset", "更新时间":"Updated",
    "视觉预设":"Visual Presets", "正式预设 · 默认":"Official preset · Default", "正式预设":"Official preset", "扩展预设":"Extended preset",
    "现代深色":"Modern Dark", "极光玻璃":"Aurora Glass", "明亮浅色":"Clean Light", "绿色终端":"Terminal Green", "专业石墨":"Professional Graphite", "蓝色生产力":"Blue Productivity",
    "材质强度":"Material strength", "背景模糊":"Backdrop blur", "动态强度":"Motion strength", "性能模式":"Performance mode",
    "网页抓取并发":"Web scraping concurrency", "全局请求并发":"Global request concurrency", "单域名并发上限":"Per-host concurrency limit",
    "调度策略":"Scheduling policy", "目标 URL（每行一个）":"Target URLs (one per line)",
    "每行一个 URL；多个 URL 将按并发策略同时抓取":"One URL per line; multiple URLs are fetched concurrently under the scheduling policy",
    "同一 Task 的多个 URL 会在线程池中并行执行；每个域名仍受独立上限约束。Auto/Efficiency 会在低端设备上自动下调实际并发，修改后重启 Arenyxa 完全生效。":"Multiple URLs in one Task run in parallel in a thread pool; each host remains independently bounded. Auto/Efficiency reduces effective concurrency on constrained devices. Restart Arenyxa to fully apply changes.",
    "减少大幅位移、折射、粒子和连续光效":"Reduce large motion, refraction, particles, and continuous effects", "高对比度玻璃回退":"High-contrast glass fallback",
    "启用实时数据流动态":"Enable live-data motion", "启用关键状态边缘流光":"Enable status edge effect", "语言、RTL 与高级设置":"Language, RTL & advanced settings",
    "已索引页面":"Indexed pages", "存储大小（估算）":"Storage size (estimated)", "上次抓取时间":"Last capture", "存储模式":"Storage mode",
    "活动任务":"Active tasks", "本地服务":"Local service", "任务队列状态":"Task queue", "抓取进度":"Capture progress", "总体进度":"Overall progress",
    "已发现页面":"Discovered pages", "当前速度":"Current speed", "平均速度":"Average speed", "错误数":"Errors", "当前任务":"Current task",
    "定时任务":"Schedules", "最近搜索":"Recent Search", "数据统计":"Data statistics", "文件类型":"File types", "热门域名":"Top domains", "各类型内容大小":"Content size by type",
    "查看全部任务":"View all tasks", "查看全部":"View all", "暂无":"None", "暂无活动任务":"No active task", "暂无定时任务":"No schedules",
    "暂无最近索引内容":"No recent indexed content", "暂无域名统计":"No domain statistics", "尚无运行记录":"No run history", "尚无日志事件。":"No log events yet.",
    "尚无任务。使用“抓取任务”建立第一个采集任务。":"No tasks yet. Use Capture Tasks to create your first collection task.", "等待产生本地数据":"Waiting for local data",
    "等待网络事件":"Waiting for network events", "本地结构化结果":"Local structured results", "本地数据库":"Local database", "本地文件系统":"Local file system",
    "本地文件系统 · 持久化":"Local file system · persistent", "磁盘存储":"Disk storage", "在线":"Online", "运行中":"Running", "排队中":"Queued",
    "已暂停":"Paused", "已完成":"Completed", "部分完成":"Partially completed", "失败":"Failed", "已取消":"Cancelled", "待执行":"Pending",
    "已启动":"Started", "已保存任务":"Task saved", "已保存图表资产":"Chart asset saved", "已创建 Dataset Revision":"Dataset revision created",
    "导出完成":"Export completed", "导出失败":"Export failed", "搜索失败":"Search failed", "版本创建失败":"Version creation failed", "Workflow 完成":"Workflow completed",
    "Workflow 失败":"Workflow failed", "Replay 完成":"Replay completed", "Replay 失败":"Replay failed", "分析失败":"Analysis failed", "TLS 检查失败":"TLS inspection failed", "DNS 查询失败":"DNS query failed",
    "无法打开文件夹":"Unable to open folder", "无法启动":"Unable to start", "无法开始捕获":"Unable to start capture", "停止失败":"Stop failed",
    "请求":"Request", "HTTP 方法":"HTTP method", "请求正文":"Request body", "副作用确认":"Side-effect confirmation", "可能修改目标系统，是否继续？":"This may modify the target system. Continue?",
    "授权分析 URL":"Authorized analysis URL", "受控浏览器入口 URL":"Controlled browser entry URL", "进程连接快照":"Process connection snapshot", "进程监控失败":"Process monitoring failed",
    "项目无法打开":"Unable to open project", "项目已验证":"Project validated", "当前窗口暂不支持此操作":"This action is not supported in the current window",
    "检测到上次异常退出；可在日志与诊断查看详情，或使用 --safe-mode 启动。":"The previous session ended unexpectedly. Check Logs & Diagnostics or start with --safe-mode.",
    "已请求协作式取消所有活动任务":"Cooperative cancellation requested for all active tasks", "活动任务暂停/恢复状态已更新":"Active-task pause/resume state updated",
    "请选择两个 Revision。":"Select two revisions.", "请选择包含 URL 的网络请求。":"Select a network request containing a URL.", "请选择包含 Host 的事件。":"Select an event containing a Host.",
    "请选择包含结果的 Run。":"Select a run containing results.", "请先创建任务":"Create a task first", "请先创建任务。":"Create a task first.",
    "输入 JSON 数组":"Enter a JSON array", "Headers 必须是 JSON 对象。":"Headers must be a JSON object.", "输入命令或页面名称":"Enter a command or page name",
    "未知命令；输入 help。":"Unknown command; type help.", "系统命令已禁用。请在个性化/高级设置中启用 Developer Mode。":"System commands are disabled. Enable Developer Mode in Personalization/Advanced Settings.",
    "项目级工作目录；系统命令需 Developer Mode 并使用 ! 前缀":"Project working directory; system commands require Developer Mode and the ! prefix",
    "本地优先、开源的 Web 数据与网络分析平台":"Local-first, open-source web data and network analysis platform",
    "工程不变量":"Engineering invariants", "结构化 JSONL、轮转、稳定错误码、统一秘密脱敏":"Structured JSONL, rotation, stable error codes, unified secret redaction",
    "时区明确、启停可恢复、失败策略可追踪":"Explicit timezone, recoverable enable/disable, traceable failure policy", "时区":"Timezone", "间隔（分钟）":"Interval (minutes)",
    "下一次":"Next", "下次执行":"Next run", "计划执行":"Scheduled", "定时抓取":"Scheduled capture", "操作":"Actions", "状态":"Status", "启用":"Enabled",
    "插件":"Plugin", "安全关闭":"Safe shutdown", "工程不变量":"Engineering invariants", "目标":"Target", "属性":"Property", "耗时":"Duration", "平均速度":"Average speed",
    "当前速度":"Current speed", "文件类型":"File types", "本地索引":"Local index", "本地索引项":"Local index item", "本地搜索命中":"Local search hit",
    "本地搜索已索引任务、运行摘要与结构化结果":"Local search indexes tasks, run summaries, and structured results", "本地优先":"Local-first",
}

PHRASES.update({
    "发行身份、运行环境、隐私边界与项目健康信息": "Release identity, runtime environment, privacy boundaries, and project health",
    "本地优先、开源的 Web 数据采集、检索与网络分析工作台": "Local-first, open-source workspace for web collection, search, and network analysis",
    "深度验证安装": "Deep Verify Installation",
    "重新深度验证": "Verify Again",
    "正在后台验证…": "Verifying in background…",
    "复制构建信息": "Copy Build Information",
    "发行身份与完整性": "Release provenance & integrity",
    "深度文件验证尚未运行。点击“深度验证安装”可在后台核对程序文件、可加载代码、恢复包和 SQLite 数据库。": "Deep file verification has not run. Use Deep Verify Installation to check program files, loadable code, the recovery payload, and SQLite in the background.",
    "运行环境与本地数据": "Runtime environment & local data",
    "本地优先与隐私边界": "Local-first & privacy boundaries",
    "开源许可证与发行边界": "Open-source license & distribution boundaries",
    "核心能力": "Core capabilities",
    "快速状态只验证发行证明；只有“深度验证安装”才会逐文件核对安装内容。": "Quick status verifies release attestation only; Deep Verify Installation performs per-file integrity checks.",
    "当前身份状态已经包含本次深度安装完整性校验结果。": "The current identity status includes the result of this deep installation-integrity verification.",
    "正在核对发布证明、签名清单、安装文件、额外可加载代码、恢复包与 SQLite 完整性…": "Verifying release attestation, signed manifest, installed files, unexpected loadable code, recovery payload, and SQLite integrity…",
    "深度验证返回了无法识别的结果。": "Deep verification returned an unrecognized result.",
    "深度验证未返回发行完整性结果。": "Deep verification did not return a release-integrity result.",
    "构建信息已复制到剪贴板": "Build information copied to clipboard",
    "源码模式允许自由修改；完整性检查不会把正常开发修改当成需要强制恢复的篡改。": "Source mode remains freely modifiable; normal development changes are not treated as tampering that must be force-restored.",
    "发布证明由内置官方信任根验证。深度校验可进一步核对全部已签名文件与可加载代码。": "Release attestation is verified against embedded official trust roots. Deep verification can additionally check all signed files and loadable code.",
    "发布签名有效，但属于社区/第三方发行身份，不代表 Arenyxa 官方背书。": "The release signature is valid but belongs to a community/third-party identity and does not imply official Arenyxa endorsement.",
    "当前安装内容与签名发行清单不一致。软件仍可使用，但不能继续声称为未修改的已验证发行版。": "Installed content differs from the signed release manifest. The software remains usable but cannot claim to be an unmodified verified release.",
    "当前发行版没有可验证的发布证明。这不等同于恶意软件，但不能确认其官方来源。": "This distribution has no verifiable release attestation. That does not imply malware, but official origin cannot be confirmed.",
    "发布证明、签名链或发行清单无效。安装版建议运行深度验证并按结果使用自愈修复中心。": "The release attestation, signature chain, or manifest is invalid. For installed builds, run deep verification and use Repair Center according to the result.",
    "发行签名用于验证来源与完整性，不限制源码修改，也不是许可证授权、联网激活或硬件绑定。": "Release signatures verify origin and integrity; they do not restrict source modification and are not license activation, online activation, or hardware binding.",
    "• Arenyxa 核心任务、数据库、搜索索引和设置默认保存在本机，不要求 Arenyxa 官方云账户。": "• Core Arenyxa tasks, databases, search indexes, and settings are stored locally by default; no Arenyxa cloud account is required.",
    "• Arenyxa 核心采集、解析、检索、导出与网络分析采用本地确定性流程。": "• Arenyxa core collection, parsing, search, export, and network-analysis workflows use local deterministic processing.",
    "• 抓取目标网站、用户主动启用的服务器/市场/网络分析功能会按其用途访问网络；本地优先不代表“永不联网”。": "• Target-site collection and user-enabled server, marketplace, or network-analysis features access the network for their stated purpose; local-first does not mean never online.",
    "• Cookie、Authorization、Token 等敏感值在日志、诊断和插件边界默认经过脱敏策略。": "• Sensitive values such as Cookie, Authorization, and Token are redacted by default across logs, diagnostics, and plugin boundaries.",
    "发行状态": "Release state",
    "签名清单中已修改文件": "Modified signed files",
    "额外可加载文件": "Unexpected loadable files",
    "已修改": "Changed",
    "额外文件": "Unexpected",
    "说明": "Notes",
    "深度验证仅读取本机安装内容与数据库完整性信息，不需要联网。": "Deep verification reads only local installation and database-integrity information; no network connection is required.",
})

PHRASES.update({
    "Arenyxa 视觉预设只影响外观，不改变运行、权限、存储或企业策略。": "Arenyxa visual presets affect appearance only; they do not change runtime, permissions, storage, or enterprise policy.",
    "自动模式会根据 Arenyxa 窗口可用面积调整文字与常用控件尺寸，同时保留 Qt/Windows DPI 缩放；手动模式可固定 85%–160%。": "Auto mode adjusts text and common control sizes to the Arenyxa window while preserving Qt/Windows DPI scaling; manual mode can be fixed from 85% to 160%.",
    "启用 Resource Governor（推荐）": "Enable Resource Governor (recommended)",
    "Resource Governor 只能向下收紧并发，不能突破这里的用户硬上限。CPU、RAM、磁盘或浏览器压力上升时会退避；恢复必须经过连续健康采样，避免并发振荡。": "Resource Governor may only reduce concurrency and can never exceed the user hard limit. It backs off under CPU, RAM, disk, or browser pressure and requires consecutive healthy samples before recovery to avoid oscillation.",
    "诊断、Repair Center 与 Developer Mode 集中在这里。个性化主题、动效和界面缩放位于独立“个性化”页面。": "Diagnostics, Repair Center, and Developer Mode are collected here. Themes, motion, and interface scaling live on the separate Personalization page.",
    "恢复全部默认设置": "Restore all defaults",
})

                                                                                      
                                                                                

                                                                                             
PHRASES.update({
    "界面缩放与字体": "Interface scale & text",
    "自动（随窗口大小）": "Auto (follow window size)",
    "手动": "Manual",
    "缩放模式": "Scale mode",
    "手动缩放": "Manual scale",
    "说明": "Description",
    "自动模式会根据当前 Arenyxa 窗口的可用面积分级调整文字与常用控件尺寸；Qt/Windows 的 DPI 缩放仍然保留，不会重复放大。手动模式可固定 85%–160%。": "Auto mode adjusts text and common control sizes in steps based on the current Arenyxa window area. Qt/Windows DPI scaling remains authoritative and is not multiplied twice. Manual mode can be fixed from 85% to 160%.",
})

PHRASES.update({
    "导入 HAR":"Import HAR", "已导入 HAR":"HAR imported", "工作流无效":"Invalid workflow", "成功":"Success", "完成":"Completed", "错误":"Error",
    "捕获已启动":"Capture started", "捕获完成":"Capture completed", "无 URL":"No URL", "日志":"Logs", "自动化":"Automation", "任务":"Task",
    "编辑":"Edit", "启动":"Start", "渲染":"Render", "已渲染":"Rendered", "保存资产":"Save asset", "执行项目命令":"Run project command",
    "个后台任务。停止任务并退出？":" background task(s) remain. Stop them and exit?", "正在后台构建数据版本":"Building data version in the background",
    "正在后台流式导出":"Streaming export in the background", "深度":"Depth", "工作流已保存":"Workflow saved", "高级平台分析完成":"Advanced-platform analysis completed",
    "高级平台正在后台分析":"Advanced-platform analysis running in the background", "无法写入 PNG":"Unable to write PNG", "中执行":"Executing", "项":"items", "是":"Yes", "否":"No",
    "在":"at", "已":"Done", "仍有":"There are still", "个排队":"queued", "个请求":"requests", "运行中 · 共":"Running · total", "vs 上次抓取":"vs previous capture",
    "优先级：中":"Priority: medium", "接口编号或名称":"interface number or name", "默认仅绑定":"binds only by default", "权限未要求":"permission not requested",
    "可追踪；回滚产生新":"traceable; rollback creates a new", "定义与":"definition and", "事实分离，历史":"facts are separated; historical", "保留配置快照":"keeps a configuration snapshot",
    "分页浏览、来源追踪、版本化、流式":"Paged browsing, provenance tracking, versioning, streaming", "与用户控制存储":"and user-controlled storage",
    "六套视觉预设拥有独立的色彩、玻璃材质与工作台预览；切换主题不会改变业务状态":"Six visual presets have distinct color/material previews while preserving business state",
    "复古终端 / 荧光绿 / 低圆角科技感":"Retro terminal / phosphor green / low-radius technical style", "极光液态玻璃 / 青绿光晕 / 深海渐变":"Aurora liquid glass / cyan-green glow / deep-ocean gradient",
    "石墨灰 / 克制玻璃 / 企业专业感":"Graphite gray / restrained glass / enterprise professional", "高信息密度 / 专业工作台":"high information density / professional workstation",
    "清洁留白 / 绿色强调":"clean whitespace / green accent", "明亮商务 / 高可读性":"bright business / high readability",
    "允许经确认的项目级终端命令":"allows confirmed project-level terminal commands", "选择任务、运行、请求或数据记录以查看上下文":"Select a task, run, request, or data record to inspect context",
    "选择 Run 与字段生成可视化":"Select a Run and fields to create a visualization", "仪表盘上下文":"Dashboard context", "无任务运行":"No task is running",
    "结果、数据库查询或 Dataset Revision → 图表资产 → PNG/报告数据":"Results, database query, or Dataset Revision → chart asset → PNG/report data",
    "确定性执行规划、站点地图、API Map、性能与安全配置分析":"Deterministic execution planning, site map, API Map, performance and security configuration analysis",
    "Manifest、显式授权、子进程隔离、超时与输出预算":"Manifest, explicit authorization, subprocess isolation, timeout, and output budget",
    "本地网页搜索引擎":"Local web search engine", "本地捕获数据":"local capture data", "输入 help 查看受控命令":"Type help to view controlled commands",
    "请先选择包含 Host 的事件":"Select an event containing Host first", "明亮商务":"bright business", "高可读性":"high readability",
    "• 本地优先，用户控制数据与存储位置\n• Task 与 Run 分离，历史事实可追溯\n• 敏感信息默认脱敏，明文访问需要显式动作\n• 后台任务不阻塞 GUI，取消与恢复边界明确\n• 关闭透明、动画或 GPU 增强后全部核心功能仍可用":"• Local-first; users control data and storage\n• Task and Run are separated; historical facts remain traceable\n• Sensitive information is redacted by default; plaintext access is explicit\n• Background jobs never block the GUI; cancel/recovery boundaries are explicit\n• Core functionality remains available with transparency, motion, and GPU enhancements disabled",
    "正式预设保留既定 Arenyxa 视觉基线；Professional Graphite 与 Blue Productivity 作为 Codex 扩展预设继续保留。":"Official presets preserve the established Arenyxa visual baseline; Professional Graphite and Blue Productivity remain as extended presets.",
})

PHRASES.update({
    "发行身份与完整性": "Release provenance & integrity",
    "源码 / 开发构建": "Source / Development build",
    "已验证官方版本": "Verified official build",
    "已验证社区版本": "Verified community build",
    "已修改版本": "Modified build",
    "未验证发行版": "Unverified distribution",
    "发行签名无效": "Invalid release attestation",
    "源码模式允许自由修改，防篡改模块不会自动把开发者的代码恢复为旧版本。": "Source mode is intentionally editable; anti-tamper will not automatically restore developer changes to an older version.",
    "发行签名与可信官方公钥匹配；该状态仅证明来源与完整性。": "The release signature matches a trusted official public key; this status proves provenance and integrity only.",
    "发行签名有效，但属于社区/第三方发行身份，不代表 Arenyxa 官方背书。": "The release signature is valid, but this is a community/third-party distribution and does not imply official Arenyxa endorsement.",
    "当前安装内容与签名发行清单不一致；软件仍可运行，但不能继续声称为未修改的官方发行版。": "Installed content differs from the signed release manifest; the software remains usable but cannot claim unmodified official provenance.",
    "当前发行版没有可用的可信发布证明；这不等同于恶意软件，但不能验证其官方来源。": "No trusted release proof is available; this does not imply malware, but official provenance cannot be verified.",
    "发布证明或签名链无效。若这是安装版，建议使用自愈修复中心检查程序文件。": "The release proof or signature chain is invalid. For an installed build, use Repair Center to check program files.",
    "发行身份检查已完成。": "Release provenance check completed.",
    "GPL-3.0-or-later 允许使用、修改、再分发和合法商业分发；“已验证官方版本”只表示发行来源可验证，并不是功能授权或 DRM。修改版与第三方版本应明确标识自身来源，并遵守适用的 GPL 许可证与对应源码义务。": "GPL-3.0-or-later permits use, modification, redistribution, and lawful commercial distribution. Verified official build only means release provenance is verifiable; it is not a feature license or DRM. Modified and third-party builds should identify their provenance clearly and comply with applicable GPL license and corresponding-source obligations.",
})

PHRASES.update({
    "个性化与设置": "Personalization & Settings",
    "视觉、语言、性能与高级维护入口；高级工具不会干扰日常工作区": "Visuals, language, performance, and advanced maintenance in one place; advanced tools stay out of the daily workspace.",
    "语言与 RTL": "Language & RTL",
    "高级设置": "Advanced Settings",
    "维护与开发工具集中在这里。Developer Mode 只控制开发者入口与受控系统命令；核心抓取、搜索、数据和网络功能不受影响。": "Maintenance and developer tools are kept here. Developer Mode controls developer entry points and confirmed system commands; core capture, search, data, and network features are unaffected.",
    "Developer Mode（显示开发者工具；系统命令仍需逐次确认）": "Developer Mode (show developer tools; system commands still require confirmation each time)",
    "我已阅读并同意开发者风险协议": "I have read and accept the developer risk agreement",
    "我已阅读并同意测试免责协议": "I have read and accept the test waiver",
    "运行诊断": "Run Diagnostics",
    "打开 Repair Center": "Open Repair Center",
    "导出诊断包": "Export Diagnostic Package",
    "尚未在本次会话中运行诊断。": "Diagnostics have not been run in this session.",
    "诊断包包含本机路径（默认关闭）": "Include local paths in diagnostic packages (off by default)",
    "恢复默认设置": "Restore Default Settings",
    "仅重置应用设置；不会删除 Projects、Captures、Exports 或正式结果数据": "Reset application settings only; Projects, Captures, Exports, and formal result data are not deleted.",
    "正在后台运行健康诊断…": "Running health diagnostics in the background…",
    "诊断完成：未发现需要处理的异常。": "Diagnostics complete: no actionable issues were found.",
    "诊断完成：系统健康": "Diagnostics complete: system healthy",
    "诊断完成：发现需要关注的项目": "Diagnostics complete: attention is required",
    "诊断失败": "Diagnostics failed",
    "正在生成脱敏诊断包…": "Generating a redacted diagnostic package…",
    "诊断包导出完成": "Diagnostic package exported",
    "导出诊断包失败": "Failed to export diagnostic package",
    "设置已恢复默认值": "Settings restored to defaults",
    "Developer Mode 未启用；请在设置 → 高级设置中启用。": "Developer Mode is disabled; enable it in Settings → Advanced Settings.",
    "Developer Mode 已启用": "Developer Mode enabled",
    "Developer Mode 已关闭": "Developer Mode disabled",
    "仍有": "There are still",
    "个后台任务。开始修复将停止任务并退出 Arenyxa。继续？": "background tasks. Starting repair will stop them and exit Arenyxa. Continue?",
})

PHRASES.update({
    "正式预设保留既定 Arenyxa 视觉基线；Professional Graphite 与 Blue Productivity 作为扩展预设继续保留。": "Official presets preserve the established Arenyxa visual baseline; Professional Graphite and Blue Productivity remain as extended presets.",
    "仅重置应用设置并关闭 Developer Mode。Projects、Captures、Exports、数据库与正式结果数据不会删除。继续？": "Reset application settings and disable Developer Mode only. Projects, Captures, Exports, databases, and formal result data will not be deleted. Continue?",
    "设置已恢复默认值。原设置文件已备份；用户数据未删除。": "Settings were restored to defaults. The previous settings file was backed up; user data was not deleted.",
    "诊断完成：发现 ": "Diagnostics complete: found ",
    " 项异常，涉及 ": " issues across ",
    " 类，其中 ": " categories, including ",
    " 项为关键问题。可打开 Repair Center 自动处理。": " critical issues. Open Repair Center for automatic remediation.",
    "诊断失败：": "Diagnostics failed: ",
    "诊断包已导出：": "Diagnostic package exported: ",
    "诊断包导出失败：": "Diagnostic package export failed: ",
    "Headless Server 默认仅绑定 loopback": "Headless Server binds to loopback by default",
    "项目已验证：": "Project validated: ",
    "运行失败": "Run failed",
    "已启动 ": "Started ",
    "个后台任务。开始修复将停止任务并退出 Arenyxa。继续？": " background tasks are still active. Starting repair will stop them and exit Arenyxa. Continue?",
    "个后台任务。停止任务并退出？": " background tasks are still active. Stop them and exit?",
})

                                                                                       
                                                                              
PHRASES.update({
    "▷  开始抓取": "▷  Start Capture",
    "Ⅱ  暂停": "Ⅱ  Pause",
    "■  停止": "■  Stop",
    "⌕  打开搜索页面": "⌕  Open Search Page",
    "▣  打开数据文件夹": "▣  Open Data Folder",
    "⌁  仪表盘": "⌁  Dashboard",
    "当前任务：": "Current task:",
    "IDLE · 0 events · 0 B · Dropped 0 · 权限未要求": "IDLE · 0 events · 0 B · Dropped 0 · permission not requested",
    "模式": "Mode",
    "清屏": "Clear",
    "• Arenyxa 核心任务、数据库、搜索索引和设置默认保存在本机，不要求 Arenyxa 官方云账户。\n• Arenyxa 核心采集、解析、检索、导出与网络分析采用本地确定性流程。\n• 抓取目标网站、用户主动启用的服务器/市场/网络分析功能会按其用途访问网络；本地优先不代表“永不联网”。\n• Cookie、Authorization、Token 等敏感值在日志、诊断和插件边界默认经过脱敏策略。":
        "• Arenyxa core tasks, databases, search indexes, and settings stay local by default; no official Arenyxa cloud account is required.\n• Arenyxa core capture, parsing, search, export, and network analysis use local deterministic processing.\n• Target websites and user-enabled server, marketplace, or network-analysis features access the network when their function requires it; local-first does not mean never online.\n• Sensitive values such as Cookie, Authorization, and Token are redacted by default at logging, diagnostics, and plugin boundaries.",
})


PHRASES.update({
    "自动调节全局请求并发（推荐）": "Automatically tune global request concurrency (recommended)",
    "Arenyxa 会把上面的“全局请求并发”作为硬上限。启用自动调节后，运行时从保守预算开始，仅在本地解析/提取 P95 保持健康且仍有排队需求时逐步放大；出现本地处理压力会自动回退。网络响应慢不会直接触发全局降载，单域名仍由独立自适应限速器控制。":
        "Arenyxa treats the global request concurrency setting above as a hard ceiling. With automatic tuning enabled, runtime starts conservatively and grows only while local parse/extract P95 stays healthy and demand remains queued; local processing pressure triggers automatic backoff. Slow network responses do not directly reduce the global budget, and each host remains governed by its independent adaptive rate limiter.",
    "全局请求并发上限": "Global request concurrency ceiling",
})

S2T = str.maketrans("仪盘网数据务录设图现览储显开关态线为体时发页签统误过滤导出进启闭优级项类区径边检测标实长动获压应际这与个门还无简从后续组总创删将话认请选", "儀盤網數據務錄設圖現覽儲顯開關態線為體時發頁籤統誤過濾導出進啟閉優級項類區徑邊檢測標實長動獲壓應際這與個門還無簡從後續組總創刪將話認請選")


COMMON_NATIVE = {
    "fr_FR": {"Dashboard":"Tableau de bord","Start Capture":"Démarrer la collecte","Pause":"Pause","Stop":"Arrêter","Open Search Page":"Ouvrir la recherche","Open Data Folder":"Ouvrir le dossier de données","Indexed pages":"Pages indexées","Storage size (estimated)":"Stockage (estimé)","Last capture":"Dernière collecte","Storage mode":"Mode de stockage","Active tasks":"Tâches actives","Local service":"Service local","Task queue":"File des tâches","Capture progress":"Progression de la collecte","Overall progress":"Progression globale","Discovered pages":"Pages découvertes","Current speed":"Vitesse actuelle","Average speed":"Vitesse moyenne","Errors":"Erreurs","Schedules":"Planifications","Recent Search":"Recherches récentes","Data statistics":"Statistiques des données","File types":"Types de fichiers","Top domains":"Domaines principaux","Content size by type":"Taille par type","View all":"Tout afficher","No active task":"Aucune tâche active","No schedules":"Aucune planification","Personalization":"Personnalisation","Visual Presets":"Préréglages visuels","Material strength":"Intensité du matériau","Backdrop blur":"Flou d’arrière-plan","Motion strength":"Intensité des animations","Performance mode":"Mode de performance","Interface language":"Langue de l’interface"},
    "de_DE": {"Dashboard":"Übersicht","Start Capture":"Erfassung starten","Pause":"Pause","Stop":"Stopp","Open Search Page":"Suche öffnen","Open Data Folder":"Datenordner öffnen","Indexed pages":"Indexierte Seiten","Storage size (estimated)":"Speichergröße (geschätzt)","Last capture":"Letzte Erfassung","Storage mode":"Speichermodus","Active tasks":"Aktive Aufgaben","Local service":"Lokaler Dienst","Task queue":"Aufgabenwarteschlange","Capture progress":"Erfassungsfortschritt","Overall progress":"Gesamtfortschritt","Discovered pages":"Gefundene Seiten","Current speed":"Aktuelle Geschwindigkeit","Average speed":"Durchschnitt","Errors":"Fehler","Schedules":"Zeitpläne","Recent Search":"Letzte Suchen","Data statistics":"Datenstatistik","File types":"Dateitypen","Top domains":"Top-Domains","Content size by type":"Inhaltsgröße nach Typ","View all":"Alle anzeigen","No active task":"Keine aktive Aufgabe","No schedules":"Keine Zeitpläne","Personalization":"Personalisierung","Visual Presets":"Visuelle Presets","Material strength":"Materialstärke","Backdrop blur":"Hintergrundunschärfe","Motion strength":"Animationsstärke","Performance mode":"Leistungsmodus","Interface language":"Oberflächensprache"},
    "ru_RU": {"Dashboard":"Панель","Start Capture":"Начать сбор","Pause":"Пауза","Stop":"Стоп","Open Search Page":"Открыть поиск","Open Data Folder":"Открыть папку данных","Indexed pages":"Индексированные страницы","Storage size (estimated)":"Размер хранилища","Last capture":"Последний сбор","Storage mode":"Режим хранения","Active tasks":"Активные задачи","Local service":"Локальный сервис","Task queue":"Очередь задач","Capture progress":"Ход сбора","Overall progress":"Общий прогресс","Discovered pages":"Найденные страницы","Current speed":"Текущая скорость","Average speed":"Средняя скорость","Errors":"Ошибки","Schedules":"Расписания","Recent Search":"Недавний поиск","Data statistics":"Статистика данных","File types":"Типы файлов","Top domains":"Популярные домены","Content size by type":"Размер по типам","View all":"Показать все","No active task":"Нет активной задачи","No schedules":"Нет расписаний","Personalization":"Персонализация","Visual Presets":"Визуальные профили","Material strength":"Интенсивность материала","Backdrop blur":"Размытие фона","Motion strength":"Интенсивность анимации","Performance mode":"Режим производительности","Interface language":"Язык интерфейса"},
    "ja_JP": {"Dashboard":"ダッシュボード","Start Capture":"取得開始","Pause":"一時停止","Stop":"停止","Open Search Page":"検索を開く","Open Data Folder":"データフォルダーを開く","Indexed pages":"インデックス済みページ","Storage size (estimated)":"ストレージ使用量（推定）","Last capture":"前回の取得","Storage mode":"保存モード","Active tasks":"実行中タスク","Local service":"ローカルサービス","Task queue":"タスクキュー","Capture progress":"取得進捗","Overall progress":"全体進捗","Discovered pages":"検出ページ","Current speed":"現在速度","Average speed":"平均速度","Errors":"エラー","Schedules":"スケジュール","Recent Search":"最近の検索","Data statistics":"データ統計","File types":"ファイル種類","Top domains":"上位ドメイン","Content size by type":"種類別サイズ","View all":"すべて表示","No active task":"実行中タスクなし","No schedules":"スケジュールなし","Personalization":"パーソナライズ","Visual Presets":"ビジュアルプリセット","Material strength":"マテリアル強度","Backdrop blur":"背景ぼかし","Motion strength":"モーション強度","Performance mode":"性能モード","Interface language":"表示言語"},
    "ko_KR": {"Dashboard":"대시보드","Start Capture":"수집 시작","Pause":"일시 중지","Stop":"중지","Open Search Page":"검색 열기","Open Data Folder":"데이터 폴더 열기","Indexed pages":"색인된 페이지","Storage size (estimated)":"저장 공간(예상)","Last capture":"최근 수집","Storage mode":"저장 모드","Active tasks":"활성 작업","Local service":"로컬 서비스","Task queue":"작업 대기열","Capture progress":"수집 진행률","Overall progress":"전체 진행률","Discovered pages":"발견된 페이지","Current speed":"현재 속도","Average speed":"평균 속도","Errors":"오류","Schedules":"일정","Recent Search":"최근 검색","Data statistics":"데이터 통계","File types":"파일 유형","Top domains":"상위 도메인","Content size by type":"유형별 콘텐츠 크기","View all":"모두 보기","No active task":"활성 작업 없음","No schedules":"일정 없음","Personalization":"개인 설정","Visual Presets":"시각 프리셋","Material strength":"재질 강도","Backdrop blur":"배경 흐림","Motion strength":"모션 강도","Performance mode":"성능 모드","Interface language":"인터페이스 언어"},
    "ar_SA": {"Dashboard":"لوحة المعلومات","Start Capture":"بدء الالتقاط","Pause":"إيقاف مؤقت","Stop":"إيقاف","Open Search Page":"فتح البحث","Open Data Folder":"فتح مجلد البيانات","Indexed pages":"الصفحات المفهرسة","Storage size (estimated)":"حجم التخزين التقديري","Last capture":"آخر التقاط","Storage mode":"وضع التخزين","Active tasks":"المهام النشطة","Local service":"الخدمة المحلية","Task queue":"قائمة انتظار المهام","Capture progress":"تقدم الالتقاط","Overall progress":"التقدم الكلي","Discovered pages":"الصفحات المكتشفة","Current speed":"السرعة الحالية","Average speed":"متوسط السرعة","Errors":"الأخطاء","Schedules":"الجداول","Recent Search":"عمليات البحث الأخيرة","Data statistics":"إحصاءات البيانات","File types":"أنواع الملفات","Top domains":"أبرز النطاقات","Content size by type":"حجم المحتوى حسب النوع","View all":"عرض الكل","No active task":"لا توجد مهمة نشطة","No schedules":"لا توجد جداول","Personalization":"التخصيص","Visual Presets":"الإعدادات المرئية","Material strength":"قوة المادة","Backdrop blur":"تمويه الخلفية","Motion strength":"قوة الحركة","Performance mode":"وضع الأداء","Interface language":"لغة الواجهة"},
    "la_VA": {"Dashboard":"Tabula","Start Capture":"Incipe collectionem","Pause":"Pausa","Stop":"Siste","Open Search Page":"Aperi quaestionem","Open Data Folder":"Aperi folder datorum","Indexed pages":"Paginae indicatae","Storage size (estimated)":"Magnitudo repositorii","Last capture":"Ultima collectio","Storage mode":"Modus repositorii","Active tasks":"Munera activa","Local service":"Servitium locale","Task queue":"Ordo munerum","Capture progress":"Progressus collectionis","Overall progress":"Progressus totus","Discovered pages":"Paginae inventae","Current speed":"Celeritas praesens","Average speed":"Celeritas media","Errors":"Errores","Schedules":"Schedulae","Recent Search":"Quaestiones recentes","Data statistics":"Statistica datorum","File types":"Genera fasciculorum","Top domains":"Dominia principalia","Content size by type":"Magnitudo per genus","View all":"Omnia vide","No active task":"Nullum munus activum","No schedules":"Nullae schedulae","Personalization":"Personalizatio","Visual Presets":"Praecepta visualia","Material strength":"Vis materiae","Backdrop blur":"Obscuratio fundi","Motion strength":"Vis motus","Performance mode":"Modus efficientiae","Interface language":"Lingua interfaciei"},
}
for _locale, _phrases in NATIVE_PHRASES.items():
    COMMON_NATIVE.setdefault(_locale, {}).update(_phrases)

                                                                                        
                                                                                                 
for _locale, _table in TRANSLATIONS.items():
    if _locale in {"zh_CN", "en_US"}:
        continue
    target = COMMON_NATIVE.setdefault(_locale, {})
    for _key, _english in EN.items():
        _native = _table.get(_key)
        if _native and _native != _english:
            target.setdefault(_english, _native)

_CHINESE = re.compile(r"[\u3400-\u9fff]")

                                                                                   
                                                                                          
                                                                        
_ENGLISH_TO_ZH: dict[str, str] = {}
for _zh_source, _english_source in PHRASES.items():
    if _CHINESE.search(_zh_source) and _english_source:
        _ENGLISH_TO_ZH.setdefault(_english_source, _zh_source)
for _key, _english_source in EN.items():
    _zh_source = ZH_CN.get(_key)
    if _zh_source and _zh_source != _english_source:
        _ENGLISH_TO_ZH.setdefault(_english_source, _zh_source)

                                                                                         
                                                                                             
_V653_ENGLISH_TO_ZH = {
    "Active request budget": "当前请求预算",
    "Analyze GraphQL / WebSocket / SSE": "分析 GraphQL / WebSocket / SSE",
    "Analyze Quality & Schema": "分析质量与 Schema",
    "Analyze → Explain → Blueprint": "分析 → 解释 → 蓝图",
    "Apply Request Budget": "应用请求预算",
        "Breakpoints": "断点",
    "Browser Profile Manager": "浏览器配置管理",
    "Cancel All": "全部取消",
    "Clean / Deduplicate": "清洗 / 去重",
    "Continue": "继续",
    "Create .venv": "创建 .venv",
    "Create / Ensure Project Env": "创建 / 确保项目环境",
    "Create in Project": "在项目中创建",
    "Delete": "删除",
    "Experience Stats": "经验统计",
    "Export Safe Metadata": "导出安全元数据",
    "Generate Code": "生成代码",
    "Generate Workflow + Playwright": "生成 Workflow + Playwright",
    "Health": "健康状态",
    "Inputs": "输入",
    "Install Packages": "安装包",
    "Install Selected": "安装所选项",
    "Load Environment": "加载环境",
    "Load Marketplace": "加载市场",
    "Load Profile": "加载配置",
    "Pause / Resume All": "全部暂停 / 继续",
    "Prepare": "准备",
    "Preview Partition": "预览分区",
    "Preview Template": "预览模板",
    "Python Env Status": "Python 环境状态",
    "Record Live Browser": "录制实时浏览器",
    "Refresh names": "刷新名称",
    "Register / Update": "注册 / 更新",
    "Remote Runs": "远程运行",
    "Remote Tasks": "远程任务",
    "Request → Workflow": "请求 → 工作流",
    "Resolve Variables": "解析变量",
    "Reveal once": "显示一次",
    "Run Headless": "无头运行",
    "Run Offline Compatibility Baseline": "运行离线兼容性基线",
    "Run Remote Task": "运行远程任务",
    "Save / Update": "保存 / 更新",
    "Save Environment": "保存环境",
    "Save Profile": "保存配置",
    "Self-Heal": "自修复",
    "Send + Assertions": "发送 + 断言",
    "Simulate Adaptive Rate Decision": "模拟自适应速率决策",
    "Step": "单步",
    "Validate / Import Document": "验证 / 导入文档",
    "Workflow → Debugger": "工作流 → 调试器",
    "Workflow Debugger": "工作流调试器",
    "Browser Recorder": "浏览器录制器",
    "Data Quality Studio": "数据质量工作台",
    "HTTP Request Builder": "HTTP 请求构建器",
    "Protocol Inspector": "协议检查器",
    "Selector Studio": "选择器工作台",
    "Secrets Vault": "密钥保险库",
    "Distributed Workers": "分布式 Worker",
    "Project Environment": "项目环境",
    "Workflow Marketplace": "工作流市场",
    "Workflow Portability": "工作流可移植性",
        "Compatibility Lab": "兼容性实验室",
    "Autopilot Learning": "Autopilot 学习",
    "Overview": "概览",
    "Headers": "请求头",
    "Timing": "时序",
    "Request Replay": "请求重放",
    "TLS Inspector": "TLS 检查器",
    "DNS Analyzer": "DNS 分析器",
    "Process Monitor": "进程监视器",
    "Database Adapter": "数据库适配器",
    "Analyze Autopilot": "分析 Autopilot",
    "Analyze SmartPath 2.0": "分析 SmartPath 2.0",
    "Analyze / Generate Candidates": "分析 / 生成候选",
    "Refresh Live Center": "刷新 Live Center",
    "Export Redacted Training JSONL": "导出去标识化训练 JSONL",
    "Deterministic strategy + local feedback learning. URLs, DOM, headers, cookies, tokens, and user prompts are not stored by default.": "确定性策略 + 本地反馈学习。默认不保存 URL、DOM、Header、Cookie、Token 或用户提示词。",
    "Results": "结果",
    "Record Failure": "记录失败",
    "Record Success": "记录成功",
    "Canonical portable document / validation result": "规范可移植文档 / 验证结果",
    "Default Browser Profile": "默认浏览器配置",
    "Deterministic fixtures only · suitable for CI regression; not a live-web compatibility claim.": "仅使用确定性测试夹具 · 适用于 CI 回归，不代表实时网站兼容性。",
    "Explainable decision trace · engine cost/stability estimates · fallback chain · starter workflow": "可解释决策轨迹 · 引擎成本/稳定性估计 · 回退链 · 起始工作流",
    "Export arenyxa.workflow/v1": "导出 arenyxa.workflow/v1",
    "HTML / DOM Snapshot": "HTML / DOM 快照",
    "HTTP status": "HTTP 状态",
    "Imported → Debugger": "已导入 → 调试器",
    "Project Python": "项目 Python",
    "Recorder events JSON": "录制事件 JSON",
    "Reviewable JSON workflow source": "可审阅的 JSON 工作流源码",
    "Top API → HTTP Builder": "主要 API → HTTP 构建器",
    "Variable scopes (secret.* resolves via Secrets Vault)": "变量作用域（secret.* 通过密钥保险库解析）",
    "Workflow Marketplace (optional, checksum-verified)": "工作流市场（可选，校验和验证）",
    "Traffic by domain": "按域名统计流量",
    "records": "条记录",
    "Settings": "设置",
    "About": "关于",
}
_ENGLISH_TO_ZH.update(_V653_ENGLISH_TO_ZH)

_V655_ENGLISH_TO_ZH = {
    "Recovery & Health Center": "运行恢复与健康中心",
    "Resume interrupted workflows and inspect scheduler / worker health without deleting user data.": "恢复中断的工作流，并检查调度器 / Worker 健康状态；不会删除用户数据。",
    "Probe Workers": "检测 Worker",
    "Resume Selected": "恢复所选项",
    "Runtime health has not been refreshed yet.": "尚未刷新运行时健康状态。",
    "Recovery": "恢复",
    "Scheduler": "调度器",
    "Workers": "Worker",
    "Recovery History": "恢复历史",
    "Type": "类型",
    "State": "状态",
    "Action": "操作",
    "Details": "详情",
    "Kind": "类型",
    "Enabled": "启用",
    "Running": "运行中",
    "Pending": "等待中",
    "Status": "状态",
    "Latency / Error": "延迟 / 错误",
    "Not probed": "未检测",
    "Online": "在线",
    "Offline": "离线",
    "Disabled": "已禁用",
    "Workflow Resume": "工作流恢复",
    "Worker Health": "Worker 健康状态",
    "No recovery history yet.": "暂无恢复历史。",
    "Resumable workflows": "可恢复工作流",
    "Blocked workflows": "受阻工作流",
    "Interrupted revisions": "中断修订",
    "Active runs": "活动 Run",
    "enabled": "已启用",
    "Workflow": "工作流",
    "Dataset Revision": "数据集修订",
    "Schedule": "计划",
    "interrupted": "已中断",
    "invalid": "无效",
    "Resume": "恢复",
    "Blocked": "受阻",
    "Inspect": "检查",
    "Repair Center": "修复中心",
    "Durable checkpoint is valid": "持久化检查点有效",
    "Resume chain is incomplete or inconsistent": "恢复链不完整或状态不一致",
    "Source run metadata is preserved; automatic replay is intentionally not assumed": "源 Run 元数据已保留；不会擅自假定可自动重放。",
    "Source metadata is incomplete": "源元数据不完整",
    "Invalid persisted schedule definition": "持久化计划定义无效",
    "Refreshing runtime health…": "正在刷新运行时健康状态…",
    "Runtime health refreshed": "运行时健康状态已刷新",
    "Runtime Health": "运行时健康状态",
    "Resuming workflow from durable checkpoint…": "正在从持久化检查点恢复工作流…",
    "Workflow resume completed": "工作流恢复完成",
    "Workflow recovery": "工作流恢复",
    "Probing configured workers…": "正在检测已配置的 Worker…",
    "Worker health probe completed": "Worker 健康检测完成",
    "Recovery history is unavailable": "恢复历史不可用",
}
_ENGLISH_TO_ZH.update(_V655_ENGLISH_TO_ZH)

_TRANSLATABLE_ENGLISH = set(_ENGLISH_TO_ZH)
_TRANSLATABLE_ENGLISH.update(EN.values())
for _native_table in COMMON_NATIVE.values():
    _TRANSLATABLE_ENGLISH.update(_native_table.keys())


def _is_translatable_ui_literal(text: str) -> bool:
    




    candidate = str(text or "").strip()
    if not candidate:
        return False
    if _CHINESE.search(candidate):
        return True
    if candidate in _TRANSLATABLE_ENGLISH:
        return True
    if re.fullmatch(r"\d+\s+(?:records|items|rows|events|issues?)", candidate, flags=re.IGNORECASE):
        return True
                                                                                   
    for phrase in _TRANSLATABLE_ENGLISH:
        if len(phrase) >= 10 and phrase in candidate:
            return True
    return False


def resolve_system_locale() -> str:
    name = QLocale.system().name().replace("-", "_")
    language = name.split("_", 1)[0].casefold()
    if language == "zh":
        return "zh_TW" if any(tag in name.upper() for tag in ("TW", "HK", "MO", "HANT")) else "zh_CN"
    mapping = {"en":"en_US","fr":"fr_FR","ru":"ru_RU","de":"de_DE","ja":"ja_JP","ko":"ko_KR","ar":"ar_SA","la":"la_VA"}
    return mapping.get(language, "en_US")


PHRASES.update({
    "重新选择使用模式": "Choose work mode again",
    "使用模式只调整工作区呈现与默认导航，不是权限等级。Developer / Enterprise 权限始终由后端安全策略决定；主题和预设仍在独立“个性化”页面。": "Work mode changes workspace presentation and default navigation only; it is not an authority level. Developer and Enterprise permissions are always decided by backend security policy; themes and presets remain in Personalization.",
    "使用此模式": "Use this mode",
    "企业环境入口已经预留，但 Phase 4–5 不伪造尚未实现的 Enterprise Identity / Vault / RBAC。 Create Enterprise / Join Enterprise 将在对应安全后端真正完成后启用。": "The Enterprise entry is reserved, but Phase 4–5 does not fake Enterprise Identity, Vault, or RBAC. Create Enterprise / Join Enterprise will be enabled only after the corresponding security backend is real.",
    "企业环境 · 后续阶段启用": "Enterprise · available in a later phase",
    "Server / Worker · 尚未开放": "Server / Worker · not yet available",
    "之后可以在 设置 → 使用模式 中重新打开此页面。主题、字体、界面缩放与动效继续放在独立“个性化”页面。": "You can reopen this page later from Settings → Work Mode. Themes, typography, UI scale and motion remain in the separate Personalization page.",
})

def literal_for_locale(source: str, locale: str) -> str:
    





    if not source:
        return source
    if locale in {"zh_CN", "zh_TW"}:
        chinese = source if _CHINESE.search(source) else _ENGLISH_TO_ZH.get(source, source)
        if chinese == source and not _CHINESE.search(source):
                                                                                      
            chinese = source
            for english_phrase, zh_phrase in sorted(_ENGLISH_TO_ZH.items(), key=lambda item: len(item[0]), reverse=True):
                if len(english_phrase) >= 10 and english_phrase in chinese:
                    chinese = chinese.replace(english_phrase, zh_phrase)
                elif re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{2,11}", english_phrase):
                    chinese = re.sub(
                        rf"(?<![A-Za-z0-9_]){re.escape(english_phrase)}(?![A-Za-z0-9_])",
                        zh_phrase,
                        chinese,
                    )
        return chinese.translate(S2T) if locale == "zh_TW" else chinese

    english = PHRASES.get(source)
    if english is None:
        english = source
        safe_single = {"是": "Yes", "否": "No", "项": "items", "已": "Done"}
        if source in safe_single:
            english = safe_single[source]
        else:
            for zh, replacement in sorted(PHRASES.items(), key=lambda item: len(item[0]), reverse=True):
                if len(zh) > 1:
                    english = english.replace(zh, replacement)
            english = english.replace(" 项", " items")
            if english.startswith("已") and len(english) > 1:
                english = "Done " + english[1:]
            if english.startswith("在 "):
                english = "at " + english[2:]

    english = english.translate(str.maketrans({"：": ":", "。": ".", "，": ",", "；": ";", "（": "(", "）": ")"}))
    if " / " in english:
        left, right = (part.strip() for part in english.split(" / ", 1))
        if left.casefold() == right.casefold():
            english = left
    if _CHINESE.search(english):
        residual = _CHINESE.sub("", english)
        residual = re.sub(r"\s{2,}", " ", residual).strip(" ·-—:：()（）")
        english = residual if residual and any(ch.isalnum() for ch in residual) else "Untranslated diagnostic"

    result = english
    for english_phrase, native in sorted(COMMON_NATIVE.get(locale, {}).items(), key=lambda item: len(item[0]), reverse=True):
        if not english_phrase or english_phrase == native:
            continue
        if re.fullmatch(r"[A-Za-z0-9 _-]{1,12}", english_phrase) and " " not in english_phrase.strip():
            result = re.sub(rf"(?<![A-Za-z0-9_]){re.escape(english_phrase)}(?![A-Za-z0-9_])", native, result)
        else:
            result = result.replace(english_phrase, native)
    return result


class LanguageManager(QObject):
    






    changed = Signal(str)

    _SAFE_SINGLE_EXACT = {
        "是": "Yes",
        "否": "No",
        "项": "items",
        "已": "Done",
    }

    def __init__(self, application: QApplication, locale: str = SYSTEM_LOCALE) -> None:
        super().__init__()
        self.application = application
        self.requested_locale = locale if locale in LOCALES else SYSTEM_LOCALE
        self.locale = resolve_system_locale() if self.requested_locale == SYSTEM_LOCALE else self.requested_locale
        self._pending_widgets: set[int] = set()
                                                                                        
                                                         
        self.application.installEventFilter(self)

    def text(self, key: str) -> str:
        table = TRANSLATIONS.get(self.locale, EN)
        return table.get(key, EN.get(key, key))

    def apply(self, locale: str) -> None:
        self.requested_locale = locale if locale in LOCALES else SYSTEM_LOCALE
        self.locale = resolve_system_locale() if self.requested_locale == SYSTEM_LOCALE else self.requested_locale
        qlocale = QLocale(self.locale)
        QLocale.setDefault(qlocale)
                                                                                     
                                                                                            
                                                                                           
                                                                                        
        self.application.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
                                                                                                
                                                                                      
        for top_level in self.application.topLevelWidgets():
            try:
                top_level.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
            except RuntimeError:
                continue
        self.application.setProperty("arenyxa_locale", self.locale)
        self.application.setProperty("arenyxa_content_rtl", self.locale.startswith("ar"))
        self.changed.emit(self.requested_locale)

    def eventFilter(self, watched: QObject, event: QEvent) -> bool:
        event_type = event.type()
        if event_type == QEvent.Type.Show and isinstance(watched, QWidget):
            self._schedule_translate(watched)
        elif event_type == QEvent.Type.ChildAdded:
            child = getattr(event, "child", lambda: None)()
            if isinstance(child, QWidget):
                self._schedule_translate(child)
        return super().eventFilter(watched, event)

    def _schedule_translate(self, widget: QWidget) -> None:
        token = id(widget)
        if token in self._pending_widgets:
            return
        self._pending_widgets.add(token)

        def run() -> None:
            self._pending_widgets.discard(token)
            try:
                self.translate_tree(widget)
            except RuntimeError:
                                                                                      
                return

        QTimer.singleShot(0, run)

    @staticmethod
    def _replace_english(text: str, english: str, native: str) -> str:
        if not english or english == native:
            return text
                                                                                         
        if re.fullmatch(r"[A-Za-z0-9 _-]{1,12}", english) and " " not in english.strip():
            return re.sub(rf"(?<![A-Za-z0-9_]){re.escape(english)}(?![A-Za-z0-9_])", native, text)
        return text.replace(english, native)

    def _to_english(self, source: str) -> str:
        exact = PHRASES.get(source)
        if exact is not None:
            return exact
        exact = self._SAFE_SINGLE_EXACT.get(source)
        if exact is not None:
            return exact
        result = source
                                                                                         
                                                                                            
        for zh, english in sorted(PHRASES.items(), key=lambda item: len(item[0]), reverse=True):
            if len(zh) <= 1:
                continue
            result = result.replace(zh, english)
                                                                                            
        result = result.replace(" 项", " items")
        if result.startswith("已") and len(result) > 1:
            result = "Done " + result[1:]
        if result.startswith("在 "):
            result = "at " + result[2:]
        return result

    def literal(self, source: str) -> str:
        return literal_for_locale(source, self.locale)

    def translate_tree(self, root: QWidget) -> None:
        
        widgets: Iterable[QWidget] = [root, *root.findChildren(QWidget)]
        for widget in widgets:
            title = widget.windowTitle()
            if title:
                self._translate_text_property(widget, "window_title", widget.windowTitle, widget.setWindowTitle)

            self._apply_direction(widget)

            if isinstance(widget, (QLabel, QAbstractButton)):
                self._translate_text_property(widget, "text", widget.text, widget.setText)
            if isinstance(widget, QGroupBox):
                self._translate_text_property(widget, "group_title", widget.title, widget.setTitle)
            if isinstance(widget, QLineEdit):
                self._translate_text_property(widget, "placeholder", widget.placeholderText, widget.setPlaceholderText)
            tooltip = widget.toolTip()
            if tooltip:
                self._translate_text_property(widget, "tooltip", widget.toolTip, widget.setToolTip)

            if isinstance(widget, QTabWidget):
                for index in range(widget.count()):
                    source_key = f"i18n_tab_{index}"
                    source = widget.property(source_key)
                    current = widget.tabText(index)
                    if source is None and _is_translatable_ui_literal(current):
                        source = current
                        widget.setProperty(source_key, source)
                    if source:
                        widget.setTabText(index, self.literal(str(source)))

            if isinstance(widget, QComboBox):
                for index in range(widget.count()):
                    source_key = f"i18n_item_{index}"
                    source = widget.property(source_key)
                    current = widget.itemText(index)
                    if source is None and _is_translatable_ui_literal(current):
                        source = current
                        widget.setProperty(source_key, source)
                    if source:
                        widget.setItemText(index, self.literal(str(source)))

            if isinstance(widget, QTableWidget):
                for index in range(widget.columnCount()):
                    item = widget.horizontalHeaderItem(index)
                    if item is None:
                        continue
                    source_key = f"i18n_header_{index}"
                    source = widget.property(source_key)
                    current = item.text()
                    if source is None and _is_translatable_ui_literal(current):
                        source = current
                        widget.setProperty(source_key, source)
                    if source:
                        item.setText(self.literal(str(source)))

                                                                                          
            for attr in ("label", "center_top", "center_bottom"):
                value = getattr(widget, attr, None)
                if isinstance(value, str) and value:
                    source_key = f"i18n_attr_{attr}"
                    source = widget.property(source_key)
                    if source is None and _is_translatable_ui_literal(value):
                        source = value
                        widget.setProperty(source_key, source)
                    if source:
                        setattr(widget, attr, self.literal(str(source)))
                        widget.update()

                                                                                                    
            if isinstance(widget, QPlainTextEdit) and widget.isReadOnly():
                text = widget.toPlainText()
                key = "i18n_plain_source"
                rendered_key = "i18n_plain_rendered"
                source = widget.property(key)
                rendered = widget.property(rendered_key)
                if rendered is not None and text != str(rendered):
                    if _is_translatable_ui_literal(text) and len(text) < 2000:
                        source = text
                        widget.setProperty(key, source)
                    else:
                        widget.setProperty(key, None)
                        widget.setProperty(rendered_key, None)
                        continue
                if source is None and _is_translatable_ui_literal(text) and len(text) < 2000:
                    source = text
                    widget.setProperty(key, source)
                if source:
                    translated = self.literal(str(source))
                    widget.setPlainText(translated)
                    widget.setProperty(rendered_key, translated)

    def _apply_direction(self, widget: QWidget) -> None:
        







        arabic = self.locale.startswith("ar")

        technical = False
        if isinstance(widget, QLineEdit):
            probe = f"{widget.objectName()} {widget.placeholderText()} {widget.text()}".casefold()
            technical = any(
                token in probe
                for token in (
                    "url", "json", "code", "command", "header", "selector", "regex", "sql", "path",
                    "://", "127.0.0.1", "localhost", "\\", "/home/", "c:\\",
                )
            )
        elif isinstance(widget, QPlainTextEdit):
            probe = f"{widget.objectName()} {widget.toPlainText()[:400]}".casefold()
            technical = any(token in probe for token in ("{", "}", "http", "json", "sql", "traceback", "error_code", "127.0.0.1", "#!/"))
        elif isinstance(widget, QLabel):
            probe = widget.text()
            technical = any(token in probe for token in ("://", "127.0.0.1", "HTTP", "JSON", "SQL", "SHA-256", "PID", "ID:"))

        widget.setProperty("arenyxa_technical_ltr", bool(technical))
        widget.setLayoutDirection(Qt.LayoutDirection.LeftToRight)

        if isinstance(widget, QLabel):
            base = getattr(widget, "_arenyxa_i18n_base_alignment", None)
            if base is None:
                base = widget.alignment()
                setattr(widget, "_arenyxa_i18n_base_alignment", base)
            if arabic and not technical:
                vertical = base & (Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignBottom)
                widget.setAlignment(Qt.AlignmentFlag.AlignRight | vertical)
            else:
                widget.setAlignment(base)
        elif isinstance(widget, QLineEdit):
            base = getattr(widget, "_arenyxa_i18n_base_alignment", None)
            if base is None:
                base = widget.alignment()
                setattr(widget, "_arenyxa_i18n_base_alignment", base)
            widget.setAlignment(Qt.AlignmentFlag.AlignRight if arabic and not technical else base)
        elif isinstance(widget, QGroupBox):
            base = getattr(widget, "_arenyxa_i18n_base_alignment", None)
            if base is None:
                base = widget.alignment()
                setattr(widget, "_arenyxa_i18n_base_alignment", base)
            widget.setAlignment(Qt.AlignmentFlag.AlignRight if arabic else base)

    def _translate_text_property(self, widget: QWidget, name: str, getter, setter) -> None:
        current = getter()
        source_key = f"i18n_source_{name}"
        rendered_key = f"i18n_rendered_{name}"
        source = widget.property(source_key)
        rendered = widget.property(rendered_key)
        if rendered is not None and current != str(rendered):
                                                                                             
            if _is_translatable_ui_literal(current):
                source = current
                widget.setProperty(source_key, source)
            else:
                widget.setProperty(source_key, None)
                widget.setProperty(rendered_key, None)
                return
        if source is None and _is_translatable_ui_literal(current):
            source = current
            widget.setProperty(source_key, source)
        if source:
            translated = self.literal(str(source))
            setter(translated)
            widget.setProperty(rendered_key, translated)

                                                                                      
                                                                                              
PHRASES.update({
    "Official Developer 与公开 Developer Profile 完全分离：必须验证 Developer Certificate 信任链，再用对应设备上的 Developer Personal Private Key 完成一次性挑战。邮箱不是安全根；Enterprise 管理员也不会自动获得这些能力。": "Official Developer Access is separate from the public Developer Profile: the Developer Certificate chain must validate and the matching device-held Developer Personal Private Key must complete a one-time challenge. Email is not a trust root, and Enterprise administrators do not inherit these capabilities.",
    "Official Developer 与公开 Developer Profile 完全分离：必须验证 Developer Certificate 信任链，再用对应设备私钥完成一次性挑战。Root Owner 使用独立 Owner/Authority credential；Developer Root Private Key 不参与日常登录并应始终保持离线。邮箱不是安全根；Enterprise 管理员也不会自动获得这些能力。": "Official Developer Access is separate from the public Developer Profile: validate the Developer Certificate chain, then prove the matching device private key with a one-time challenge. Root Owner uses a separate Owner/Authority credential; the Developer Root Private Key does not participate in routine login and remains offline. Email is not a trust root, and Enterprise administrators do not inherit these capabilities.",
    "登录 Official Developer": "Sign in as Official Developer",
    "登录 Root Owner / Authority": "Sign in as Root Owner / Authority",
    "导出 Root Owner Challenge": "Export Root Owner Challenge",
    "导入 Root Owner Proof": "Import Root Owner Proof",
    "退出 Official Developer": "Sign out Official Developer",
    "Phase 7 Local Enterprise Identity 已可用：可以在本机创建 Enterprise ID、加密 Identity Vault、Local Super Administrator 和 RBAC。加入其他企业 / Enrollment / Device Trust 仍留到 Phase 8。": "Phase 7 Local Enterprise Identity is available: create an Enterprise ID, encrypted Identity Vault, Local Super Administrator, and RBAC on this device. Joining another enterprise, Enrollment, and Device Trust remain Phase 8 work.",
    "打开本地企业管理": "Open Local Enterprise Administration",
    "加入企业 · Phase 8 Enrollment 后启用": "Join Enterprise · available after Phase 8 Enrollment",
    "创建本地企业": "Create Local Enterprise",
    "解锁 Identity Vault": "Unlock Identity Vault",
    "企业登录": "Enterprise Sign-in",
    "退出企业会话": "Sign out Enterprise Session",
    "锁定 Vault": "Lock Vault",
    "角色只是产品预设；真正授权由 SecurityKernel 的 capability / policy / resource / context 决策。禁用账户、修改角色或密码会递增 auth_generation，并立即撤销对应本机会话。": "Roles are product presets; authorization is decided by SecurityKernel capability / policy / resource / context. Disabling an account or changing its role/password increments auth_generation and immediately revokes the corresponding local session.",
    "刷新账户": "Refresh Accounts",
    "新增账户": "Add Account",
    "禁用 / 启用账户": "Disable / Enable Account",
    "修改角色": "Change Roles",
    "修改密码": "Change Password",
    "删除账户": "Delete Account",
    "Vault 使用认证加密、版本化格式和同目录原子替换。备份与高风险账户治理要求最近一次 step-up authentication。恢复只能在 Vault 锁定时执行，避免用新持久状态替换仍在运行的旧授权会话。": "The Vault uses authenticated encryption, a versioned format, and same-directory atomic replacement. Backup and high-risk account governance require recent step-up authentication. Restore is allowed only while the Vault is locked so new persistent state cannot replace authorization underneath live sessions.",
    "备份 Vault": "Back Up Vault",
    "恢复 Vault": "Restore Vault",
    "加入企业、Enrollment Credential、Device Trust、Enterprise Domain Lock 和 Office Coordinator 尚未启用。局域网发现不能成为信任边界；这些能力会在后续 Phase 8–9 建立真实设备身份和防重放协议后开放。": "Join Enterprise, Enrollment Credential, Device Trust, Enterprise Domain Lock, and Office Coordinator are not enabled yet. LAN discovery is not a trust boundary; these capabilities will open after Phase 8-9 establish real device identity and replay defense.",
    "加入企业 · Phase 8": "Join Enterprise · Phase 8",
})

                                                                                  
PHRASES.update({
    "Enterprise 已进入本地身份、Enrollment、Device Trust、Office Coordinator 与 Workspace Governance 阶段。创建企业和企业治理使用独立的企业管理流程；加入企业需要一次性 Enrollment Credential。": "Enterprise now includes local identity, Enrollment, Device Trust, Office Coordinator, and Workspace Governance. Enterprise creation and governance use a dedicated administration flow; joining requires a one-time Enrollment Credential.",
    "打开企业管理": "Open Enterprise Administration",
    "Enterprise Server / Distributed Worker 已进入 Phase 11 开发运行时，并继续复用同一套 Core Runtime。打开企业管理可查看 Server、Worker、队列与远程运维状态。": "Enterprise Server / Distributed Worker is implemented in the Phase 11 development runtime and continues to reuse the same Core Runtime. Open Enterprise Management to inspect Server, Worker, queue, and remote-operations status.",
    "打开 Server / Worker 管理": "Open Server / Worker Management",
    "之后可在 设置 → 使用模式 重新打开此独立窗口。主题、字体、缩放与动效继续放在独立“个性化”页面。": "You can reopen this independent window later from Settings → Experience. Themes, fonts, scaling, and motion remain in the separate Personalization page.",
    "一次性 Enrollment Credential、批量 Campaign、设备公钥登记与 Domain Lock 已接入。": "One-time Enrollment Credentials, batch campaigns, device public-key registration, and Domain Lock are available.",
    "为账户创建 Enrollment": "Create Enrollment for Account",
    "CSV 批量导入 + Campaign": "CSV Bulk Import + Campaign",
    "查看设备": "View Devices",
    "撤销设备": "Revoke Device",
    "加入 Office Enterprise": "Join Office Enterprise",
    "重新连接 Office Enterprise": "Reconnect Office Enterprise",
    "Coordinator 当前未运行。LAN Discovery 仅用于发现，真正信任由 Enterprise Root 签名身份 + TLS 证书绑定建立。": "Coordinator is not running. LAN Discovery is only for discovery; trust is established by the Enterprise Root-signed identity plus TLS certificate binding.",
    "启动 Coordinator": "Start Coordinator",
    "停止 Coordinator": "Stop Coordinator",
    "Workspace / Team / Project 资源边界、资源级 RBAC、Quota、Approval 与 Audit Query 已接入治理层。": "Workspace / Team / Project boundaries, resource-level RBAC, Quota, Approval, and Audit Query are integrated into the governance layer.",
    "创建 Workspace": "Create Workspace",
    "登记受治理资源": "Register Governed Resource",
    "查询最近 Audit": "Query Recent Audit",
    "Enterprise Server 与 Worker 共享同一 Core Runtime / Task / Run 模型。Desktop 这里只提供受授权的远程运维视图；Server/Worker 本身仍通过独立 runtime/launcher 运行，不在 UI 内 fork 第二套执行引擎。": "Enterprise Server and Workers share the same Core Runtime / Task / Run model. Desktop exposes only authorized remote-operations views; the Server/Worker runtimes still run independently and never fork a second execution engine inside the UI.",
    "分布式队列健康": "Distributed Queue Health",
    "查看 Worker": "View Workers",
    "查看分布式 Job": "View Distributed Jobs",
})
