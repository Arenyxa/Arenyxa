# Arenyxa V6.0 UI 组件树

```text
QMainWindow Arenyxa
├─ Application Icon (verbatim user PNG)
├─ Backdrop / Aurora or preset gradient
├─ NavigationRail (collapsible, scrollable, keyboard accessible)
│  ├─ Brand / icon / collapse command
│  ├─ Dashboard
│  ├─ Capture Tasks
│  ├─ Search Center
│  ├─ Data Management
│  ├─ Network Analysis
│  ├─ Workflow
│  ├─ Automation
│  ├─ Advanced Platform
│  ├─ Visualization Studio
│  ├─ Data Version Control
│  ├─ Plugins
│  ├─ Terminal Console
│  ├─ Logs & Diagnostics
│  ├─ Personalization
│  └─ About
├─ CenterColumn
│  ├─ TopCommandBar
│  │  ├─ Run / Pause / Stop
│  │  ├─ Global Search / Ctrl+K Command Palette
│  │  ├─ Network Capture
│  │  ├─ Open Data Folder
│  │  └─ Inspector Toggle
│  └─ Stable QStackedWidget (pages are never rebuilt on theme switch)
│     ├─ Dashboard: MetricCard / TaskCard / RingGauge / Bars / Activity
│     ├─ Tasks: Search / virtual list / TaskEditor tabs / Run actions
│     ├─ Search: query / result list / preview
│     ├─ Data: Run selector / PagedResultModel / inspector / export / revision
│     ├─ Network: SessionRail / RequestModel / Waterfall / ProtocolInspector
│     ├─ Workflow: JSON graph editor / input / execution report
│     ├─ Automation: schedule table / timezone editor
│     ├─ Advanced: planner / graph / API / perf / security / DB adapter
│     ├─ Visualization: chart controls / ChartCanvas / asset/export
│     ├─ Versions: revisions / comparison
│     ├─ Plugins: discovery / manifest / permissions
│     ├─ Console: mode selector / cwd+timeout status / streaming output / Stop+Clear / history-aware input / confirmed external commands
│     ├─ Logs: structured JSONL viewer
│     ├─ Settings: theme grid / motion / locale / high contrast / developer
│     └─ About: exact icon / build info / invariants
├─ ContextInspector (collapsible)
│  ├─ Context title
│  └─ Structured object / selection / error / lineage details
├─ StatusBar
│  ├─ User-readable status
│  └─ background count / capture state / DB / refresh pacing
└─ Overlay Layer
   ├─ EdgeFlowIndicator
   ├─ CommandPalette
   ├─ Dialog / Error / confirmation
   └─ Spring fade / morph animation
```

布局不变量：主题、语言、侧栏折叠、DPI 和 Reduce Motion 变化不得移动功能入口或重建 `Task`、`Run`、表单、表格模型和捕获会话。

