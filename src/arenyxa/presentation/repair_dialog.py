from __future__ import annotations

import json
from pathlib import Path

from arenyxa.qt_compat.QtCore import Qt
from arenyxa.qt_compat.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QRadioButton,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from arenyxa.infrastructure.atomic_io import read_text_limited
from arenyxa.repair import CATEGORY_LABELS, HealthReport, RepairCategory


_TEXT = {
    "zh_CN": {
        "title": "Arenyxa 自愈修复中心",
        "prompt_title": "Arenyxa 启动健康检测",
        "prompt": "Arenyxa 检测到可能影响稳定性的异常。你是否感觉软件存在问题，并希望现在自动修复？",
        "prompt_detail": "检测到 {count} 项异常。点击“是”进入修复中心；点击“否”继续启动，本次不会修改任何文件。",
        "auto": "自动检测并修复（推荐）",
        "auto_hint": "根据启动检测、日志、数据库、程序文件哈希和运行环境自动选择修复方案。",
        "manual": "手动选择问题类型",
        "detected": "本次自动检测",
        "types": "问题类型",
        "start": "开始自动修复",
        "cancel": "取消",
        "workflow": "开始后 Arenyxa 会退出，并弹出独立修复终端。终端无需输入命令：自动备份 → 修复 → 验证 → 重启 Arenyxa → 自动关闭。",
        "safety": "安全边界：不会删除 Projects、Captures、Exports 或正式结果数据；修改配置/数据库前会自动备份。",
        "none": "没有明确匹配的类别，将执行保守的通用诊断与安全修复。",
        "post_ok": "Arenyxa 自动修复已完成并通过最终健康验证。",
        "post_partial": "自动修复已运行，但仍有未解决项目。可在修复报告中查看详情。",
        "report": "修复报告",
    },
    "zh_TW": {
        "title": "Arenyxa 自癒修復中心", "prompt_title": "Arenyxa 啟動健康檢測",
        "prompt": "Arenyxa 偵測到可能影響穩定性的異常。你是否感覺軟體存在問題，並希望現在自動修復？",
        "prompt_detail": "偵測到 {count} 項異常。按「是」進入修復中心；按「否」繼續啟動，本次不會修改任何檔案。",
        "auto": "自動偵測並修復（建議）", "auto_hint": "依啟動檢測、日誌、資料庫、程式檔雜湊與執行環境自動選擇修復方案。",
        "manual": "手動選擇問題類型", "detected": "本次自動偵測", "types": "問題類型", "start": "開始自動修復", "cancel": "取消",
        "workflow": "開始後 Arenyxa 會退出並開啟獨立修復終端。終端不需輸入命令：自動備份 → 修復 → 驗證 → 重新啟動 Arenyxa → 自動關閉。",
        "safety": "安全邊界：不會刪除 Projects、Captures、Exports 或正式結果資料；修改設定/資料庫前會自動備份。",
        "none": "沒有明確匹配的類別，將執行保守的通用診斷與安全修復。", "post_ok": "Arenyxa 自動修復已完成並通過最終健康驗證。",
        "post_partial": "自動修復已執行，但仍有未解決項目。可在修復報告中查看詳情。", "report": "修復報告",
    },
    "en_US": {
        "title": "Arenyxa Repair Center", "prompt_title": "Arenyxa Startup Health Check",
        "prompt": "Arenyxa detected issues that may affect stability. Does the app appear to have a problem, and would you like it repaired automatically now?",
        "prompt_detail": "{count} issue(s) were detected. Choose Yes to open Repair Center, or No to continue without modifying files.",
        "auto": "Detect and repair automatically (recommended)", "auto_hint": "Build a repair plan from startup checks, logs, database integrity, program hashes, and the runtime environment.",
        "manual": "Choose the problem type manually", "detected": "Detected this startup", "types": "Problem types", "start": "Start automatic repair", "cancel": "Cancel",
        "workflow": "Arenyxa will exit and open a separate repair terminal. No commands are required: backup → repair → verify → relaunch Arenyxa → close automatically.",
        "safety": "Safety boundary: Projects, Captures, Exports, and formal result data are never deleted. Configuration/database changes are backed up first.",
        "none": "No precise category matched; conservative general diagnostics and safe repairs will be used.", "post_ok": "Arenyxa automatic repair completed and passed the final health check.",
        "post_partial": "Automatic repair ran, but unresolved items remain. See the repair report for details.", "report": "Repair report",
    },
    "fr_FR": {
        "title": "Centre de réparation Arenyxa", "prompt_title": "Contrôle de santé au démarrage",
        "prompt": "Arenyxa a détecté des anomalies pouvant affecter la stabilité. Constatez-vous un problème et souhaitez-vous lancer une réparation automatique ?",
        "prompt_detail": "{count} anomalie(s) détectée(s). Oui ouvre le centre de réparation ; Non continue sans modifier les fichiers.",
        "auto": "Détecter et réparer automatiquement (recommandé)", "auto_hint": "Le plan s'appuie sur le démarrage, les journaux, la base de données, les empreintes des fichiers et l'environnement.",
        "manual": "Choisir manuellement le type de problème", "detected": "Détecté au démarrage", "types": "Types de problème", "start": "Lancer la réparation automatique", "cancel": "Annuler",
        "workflow": "Arenyxa va se fermer et ouvrir un terminal de réparation séparé. Aucune commande à saisir : sauvegarde → réparation → vérification → redémarrage → fermeture automatique.",
        "safety": "Sécurité : Projects, Captures, Exports et les résultats officiels ne sont jamais supprimés ; les fichiers modifiés sont sauvegardés d'abord.",
        "none": "Aucune catégorie précise ; un diagnostic prudent et des réparations sûres seront exécutés.", "post_ok": "La réparation automatique Arenyxa est terminée et la vérification finale a réussi.",
        "post_partial": "La réparation a été exécutée, mais certains éléments restent non résolus.", "report": "Rapport de réparation",
    },
    "de_DE": {
        "title": "Arenyxa Reparaturzentrum", "prompt_title": "Start-Gesundheitsprüfung",
        "prompt": "Arenyxa hat Auffälligkeiten erkannt, die die Stabilität beeinträchtigen können. Gibt es ein Problem und soll es jetzt automatisch repariert werden?",
        "prompt_detail": "{count} Problem(e) erkannt. Ja öffnet das Reparaturzentrum; Nein startet ohne Dateiänderungen weiter.",
        "auto": "Automatisch erkennen und reparieren (empfohlen)", "auto_hint": "Der Reparaturplan nutzt Startprüfung, Protokolle, Datenbank, Dateihashes und Laufzeitumgebung.",
        "manual": "Problemtyp manuell wählen", "detected": "Beim Start erkannt", "types": "Problemtypen", "start": "Automatische Reparatur starten", "cancel": "Abbrechen",
        "workflow": "Arenyxa wird beendet und öffnet ein separates Reparaturterminal. Keine Eingabe nötig: sichern → reparieren → prüfen → Arenyxa neu starten → automatisch schließen.",
        "safety": "Sicherheit: Projects, Captures, Exports und reguläre Ergebnisdaten werden nie gelöscht; Änderungen werden vorher gesichert.",
        "none": "Keine eindeutige Kategorie; konservative Diagnose und sichere Reparatur werden verwendet.", "post_ok": "Die automatische Arenyxa-Reparatur ist abgeschlossen und die Abschlussprüfung war erfolgreich.",
        "post_partial": "Die Reparatur wurde ausgeführt, es bleiben jedoch ungelöste Punkte.", "report": "Reparaturbericht",
    },
    "ru_RU": {
        "title": "Центр восстановления Arenyxa", "prompt_title": "Проверка при запуске",
        "prompt": "Arenyxa обнаружил аномалии, которые могут повлиять на стабильность. Есть ли проблема и запустить ли автоматическое восстановление?",
        "prompt_detail": "Обнаружено: {count}. Да — открыть центр восстановления; Нет — продолжить без изменения файлов.",
        "auto": "Автоматически определить и исправить (рекомендуется)", "auto_hint": "План строится по проверке запуска, журналам, базе данных, хэшам файлов и среде выполнения.",
        "manual": "Выбрать тип проблемы вручную", "detected": "Обнаружено при запуске", "types": "Типы проблем", "start": "Начать автоматическое восстановление", "cancel": "Отмена",
        "workflow": "Arenyxa завершится и откроет отдельный терминал восстановления. Ввод не нужен: резервная копия → исправление → проверка → перезапуск → автоматическое закрытие.",
        "safety": "Безопасность: Projects, Captures, Exports и основные результаты не удаляются; изменения предварительно резервируются.",
        "none": "Точная категория не определена; будет выполнена безопасная общая диагностика.", "post_ok": "Автоматическое восстановление Arenyxa завершено, итоговая проверка пройдена.",
        "post_partial": "Восстановление выполнено, но остались нерешённые пункты.", "report": "Отчёт о восстановлении",
    },
    "ja_JP": {
        "title": "Arenyxa 修復センター", "prompt_title": "起動時ヘルスチェック",
        "prompt": "安定性に影響する可能性のある異常を検出しました。問題を感じていますか。今すぐ自動修復しますか？",
        "prompt_detail": "{count} 件の異常を検出しました。「はい」で修復センター、「いいえ」でファイルを変更せず続行します。",
        "auto": "自動検出して修復（推奨）", "auto_hint": "起動検査、ログ、DB、プログラムハッシュ、実行環境から修復計画を作成します。",
        "manual": "問題の種類を手動選択", "detected": "今回検出", "types": "問題の種類", "start": "自動修復を開始", "cancel": "キャンセル",
        "workflow": "Arenyxa を終了して専用修復ターミナルを開きます。入力不要：バックアップ → 修復 → 検証 → Arenyxa 再起動 → 自動終了。",
        "safety": "安全性：Projects / Captures / Exports / 正式な結果データは削除しません。変更前に自動バックアップします。",
        "none": "明確な分類がないため、保守的な一般診断と安全な修復を実行します。", "post_ok": "Arenyxa の自動修復が完了し、最終ヘルスチェックに合格しました。",
        "post_partial": "修復は実行されましたが、未解決項目が残っています。", "report": "修復レポート",
    },
    "ko_KR": {
        "title": "Arenyxa 복구 센터", "prompt_title": "시작 상태 검사",
        "prompt": "안정성에 영향을 줄 수 있는 이상을 감지했습니다. 실제 문제가 있습니까? 지금 자동 복구하시겠습니까?",
        "prompt_detail": "{count}개 항목을 감지했습니다. 예: 복구 센터 열기 / 아니요: 파일 변경 없이 계속.",
        "auto": "자동 감지 및 복구(권장)", "auto_hint": "시작 검사, 로그, 데이터베이스, 프로그램 해시 및 실행 환경으로 복구 계획을 만듭니다.",
        "manual": "문제 유형 직접 선택", "detected": "이번 시작에서 감지", "types": "문제 유형", "start": "자동 복구 시작", "cancel": "취소",
        "workflow": "Arenyxa가 종료되고 별도 복구 터미널이 열립니다. 입력 불필요: 백업 → 복구 → 검증 → Arenyxa 재시작 → 자동 종료.",
        "safety": "안전: Projects, Captures, Exports 및 정식 결과 데이터는 삭제하지 않으며 변경 전 자동 백업합니다.",
        "none": "정확한 분류가 없어 보수적인 일반 진단과 안전 복구를 수행합니다.", "post_ok": "Arenyxa 자동 복구가 완료되었고 최종 상태 검사를 통과했습니다.",
        "post_partial": "복구가 실행되었지만 해결되지 않은 항목이 남아 있습니다.", "report": "복구 보고서",
    },
    "ar_SA": {
        "title": "مركز إصلاح Arenyxa", "prompt_title": "فحص صحة بدء التشغيل",
        "prompt": "اكتشف Arenyxa مشكلات قد تؤثر في الاستقرار. هل تلاحظ مشكلة وتريد إصلاحها تلقائيًا الآن؟",
        "prompt_detail": "تم اكتشاف {count} مشكلة. اختر نعم لفتح مركز الإصلاح، أو لا للمتابعة دون تعديل الملفات.",
        "auto": "اكتشاف وإصلاح تلقائي (موصى به)", "auto_hint": "ينشئ خطة إصلاح من فحص البدء والسجلات وقاعدة البيانات وبصمات الملفات وبيئة التشغيل.",
        "manual": "اختيار نوع المشكلة يدويًا", "detected": "المكتشف عند البدء", "types": "أنواع المشكلات", "start": "بدء الإصلاح التلقائي", "cancel": "إلغاء",
        "workflow": "سيغلق Arenyxa ويفتح طرفية إصلاح مستقلة. لا حاجة لإدخال أوامر: نسخ احتياطي ← إصلاح ← تحقق ← إعادة تشغيل ← إغلاق تلقائي.",
        "safety": "الأمان: لن تُحذف Projects أو Captures أو Exports أو بيانات النتائج الرسمية، ويتم النسخ الاحتياطي قبل التعديل.",
        "none": "لم تتطابق فئة محددة؛ سيُستخدم تشخيص محافظ وإصلاح آمن.", "post_ok": "اكتمل إصلاح Arenyxa التلقائي واجتاز فحص الصحة النهائي.",
        "post_partial": "تم تشغيل الإصلاح، لكن ما زالت هناك عناصر غير محلولة.", "report": "تقرير الإصلاح",
    },
    "la_VA": {
        "title": "Centrum reparationis Arenyxa", "prompt_title": "Examen salutis initii",
        "prompt": "Arenyxa vitia quae stabilitatem afficere possunt detexit. Estne difficultas et visne nunc automatice reparare?",
        "prompt_detail": "{count} vitium/vitia detecta. Ita centrum reparationis aperit; Non sine mutatione fasciculorum pergit.",
        "auto": "Automatice detege et repara (commendatur)", "auto_hint": "Consilium ex examine initii, actis, database, hash fasciculorum et ambitu fit.",
        "manual": "Genus difficultatis manu elige", "detected": "Hoc initio detectum", "types": "Genera difficultatum", "start": "Incipe reparationem automaticam", "cancel": "Abroga",
        "workflow": "Arenyxa exibit et terminale reparationis separatum aperiet. Nulla mandata scribenda: copia → reparatio → verificatio → restart → clausura automatica.",
        "safety": "Securitas: Projects, Captures, Exports et data finalia numquam delentur; ante mutationem copia servatur.",
        "none": "Genus certum non inventum; diagnosis cauta et reparatio tuta fiet.", "post_ok": "Reparatio automatica Arenyxa perfecta est et examen finale transiit.",
        "post_partial": "Reparatio facta est, sed quaedam adhuc manent.", "report": "Relatio reparationis",
    },
}

                                                                                      
_REPAIR_REPORT_NATIVE = {
    "zh_CN": {"issues_summary": "{count} 项问题 · {critical} 项严重 · {warning} 项警告", "evidence": "证据", "fingerprint": "故障指纹", "more_issues": "另有 {count} 项问题"},
    "zh_TW": {"issues_summary": "{count} 項問題 · {critical} 項嚴重 · {warning} 項警告", "evidence": "證據", "fingerprint": "故障指紋", "more_issues": "另有 {count} 項問題"},
    "en_US": {"issues_summary": "{count} issue(s) · {critical} critical · {warning} warning", "evidence": "Evidence", "fingerprint": "Fault fingerprint", "more_issues": "{count} more issue(s)"},
    "fr_FR": {"issues_summary": "{count} anomalie(s) · {critical} critique(s) · {warning} avertissement(s)", "evidence": "Preuve", "fingerprint": "Empreinte de panne", "more_issues": "{count} anomalie(s) supplémentaire(s)"},
    "de_DE": {"issues_summary": "{count} Problem(e) · {critical} kritisch · {warning} Warnung(en)", "evidence": "Nachweis", "fingerprint": "Fehlerfingerabdruck", "more_issues": "{count} weitere Problem(e)"},
    "ru_RU": {"issues_summary": "Проблем: {count} · критических: {critical} · предупреждений: {warning}", "evidence": "Данные", "fingerprint": "Отпечаток сбоя", "more_issues": "Ещё проблем: {count}"},
    "ja_JP": {"issues_summary": "{count} 件 · 重大 {critical} 件 · 警告 {warning} 件", "evidence": "根拠", "fingerprint": "障害フィンガープリント", "more_issues": "ほか {count} 件"},
    "ko_KR": {"issues_summary": "문제 {count}개 · 심각 {critical}개 · 경고 {warning}개", "evidence": "근거", "fingerprint": "오류 지문", "more_issues": "추가 문제 {count}개"},
    "ar_SA": {"issues_summary": "{count} مشكلة · {critical} حرجة · {warning} تحذير", "evidence": "الدليل", "fingerprint": "بصمة العطل", "more_issues": "{count} مشكلة إضافية"},
    "la_VA": {"issues_summary": "{count} vitia · {critical} gravia · {warning} monita", "evidence": "Indicium", "fingerprint": "Signatura vitii", "more_issues": "{count} vitia addita"},
}
for _locale, _values in _REPAIR_REPORT_NATIVE.items():
    _TEXT.setdefault(_locale, {}).update(_values)

_CATEGORY_NATIVE = {
    "en_US": {
        RepairCategory.ENCODING_UI: "Garbled text / language / font display",
        RepairCategory.STARTUP_CRASH: "Startup failure / crash / crash loop",
        RepairCategory.PROGRAM_FILES: "Missing or corrupted program files",
        RepairCategory.DEPENDENCIES: "Python / Qt / module dependencies",
        RepairCategory.DATABASE_INDEX: "Database / FTS index / WAL",
        RepairCategory.SETTINGS_UI: "Settings / theme / window layout",
        RepairCategory.PLUGINS: "Plugins / plugin permissions / plugin crashes",
        RepairCategory.CAPTURE_STACK: "Packet capture / tshark / dumpcap / process monitor",
        RepairCategory.PERMISSIONS_PATHS: "Paths / permissions / write access",
        RepairCategory.CACHE_TEMP: "Cache / temporary files / stale state",
        RepairCategory.SERVER_RUNTIME: "Local service / port / runtime",
        RepairCategory.PERFORMANCE_MOTION: "Motion / rendering / performance",
        RepairCategory.FEATURE_INTEGRATION: "Advanced features / module wiring / capability integrity",
        RepairCategory.RUNTIME_STATE: "Runtime state / interrupted jobs / recovery checkpoints",
        RepairCategory.OTHER: "Other / unknown issue",
    },
    "fr_FR": {
        RepairCategory.ENCODING_UI: "Texte illisible / langue / police",
        RepairCategory.STARTUP_CRASH: "Échec au démarrage / plantage / boucle de plantage",
        RepairCategory.PROGRAM_FILES: "Fichiers du programme manquants ou corrompus",
        RepairCategory.DEPENDENCIES: "Dépendances Python / Qt / modules",
        RepairCategory.DATABASE_INDEX: "Base de données / index FTS / WAL",
        RepairCategory.SETTINGS_UI: "Paramètres / thème / disposition de fenêtre",
        RepairCategory.PLUGINS: "Extensions / autorisations / plantages",
        RepairCategory.CAPTURE_STACK: "Capture réseau / tshark / dumpcap / processus",
        RepairCategory.PERMISSIONS_PATHS: "Chemins / autorisations / écriture",
        RepairCategory.CACHE_TEMP: "Cache / fichiers temporaires / état résiduel",
        RepairCategory.SERVER_RUNTIME: "Service local / port / exécution",
        RepairCategory.PERFORMANCE_MOTION: "Animations / rendu / performances",
        RepairCategory.FEATURE_INTEGRATION: "Fonctions avancées / intégration des modules",
        RepairCategory.RUNTIME_STATE: "État d’exécution / tâches interrompues / points de reprise",
        RepairCategory.OTHER: "Autre / problème inconnu",
    },
    "de_DE": {
        RepairCategory.ENCODING_UI: "Zeichenfehler / Sprache / Schriftanzeige",
        RepairCategory.STARTUP_CRASH: "Startfehler / Absturz / Absturzschleife",
        RepairCategory.PROGRAM_FILES: "Fehlende oder beschädigte Programmdateien",
        RepairCategory.DEPENDENCIES: "Python-/Qt-/Modul-Abhängigkeiten",
        RepairCategory.DATABASE_INDEX: "Datenbank / FTS-Index / WAL",
        RepairCategory.SETTINGS_UI: "Einstellungen / Design / Fensterlayout",
        RepairCategory.PLUGINS: "Plugins / Berechtigungen / Plugin-Abstürze",
        RepairCategory.CAPTURE_STACK: "Paketmitschnitt / tshark / dumpcap / Prozessmonitor",
        RepairCategory.PERMISSIONS_PATHS: "Pfade / Berechtigungen / Schreibzugriff",
        RepairCategory.CACHE_TEMP: "Cache / temporäre Dateien / Altzustand",
        RepairCategory.SERVER_RUNTIME: "Lokaler Dienst / Port / Laufzeit",
        RepairCategory.PERFORMANCE_MOTION: "Animation / Rendering / Leistung",
        RepairCategory.FEATURE_INTEGRATION: "Erweiterte Funktionen / Modulverdrahtung",
        RepairCategory.RUNTIME_STATE: "Laufzeitstatus / unterbrochene Aufgaben / Wiederaufnahmepunkte",
        RepairCategory.OTHER: "Sonstiges / unbekanntes Problem",
    },
    "ru_RU": {
        RepairCategory.ENCODING_UI: "Кракозябры / язык / отображение шрифтов",
        RepairCategory.STARTUP_CRASH: "Ошибка запуска / сбой / цикл сбоев",
        RepairCategory.PROGRAM_FILES: "Отсутствующие или повреждённые файлы программы",
        RepairCategory.DEPENDENCIES: "Зависимости Python / Qt / модулей",
        RepairCategory.DATABASE_INDEX: "База данных / индекс FTS / WAL",
        RepairCategory.SETTINGS_UI: "Настройки / тема / компоновка окна",
        RepairCategory.PLUGINS: "Плагины / разрешения / сбои плагинов",
        RepairCategory.CAPTURE_STACK: "Захват пакетов / tshark / dumpcap / процессы",
        RepairCategory.PERMISSIONS_PATHS: "Пути / разрешения / запись",
        RepairCategory.CACHE_TEMP: "Кэш / временные файлы / остаточное состояние",
        RepairCategory.SERVER_RUNTIME: "Локальный сервис / порт / среда выполнения",
        RepairCategory.PERFORMANCE_MOTION: "Анимация / рендеринг / производительность",
        RepairCategory.FEATURE_INTEGRATION: "Расширенные функции / подключение модулей",
        RepairCategory.RUNTIME_STATE: "Состояние выполнения / прерванные задачи / точки восстановления",
        RepairCategory.OTHER: "Другое / неизвестная проблема",
    },
    "ja_JP": {
        RepairCategory.ENCODING_UI: "文字化け / 言語 / フォント表示",
        RepairCategory.STARTUP_CRASH: "起動失敗 / クラッシュ / クラッシュループ",
        RepairCategory.PROGRAM_FILES: "プログラムファイルの欠損 / 破損",
        RepairCategory.DEPENDENCIES: "Python / Qt / モジュール依存関係",
        RepairCategory.DATABASE_INDEX: "データベース / FTS / WAL",
        RepairCategory.SETTINGS_UI: "設定 / テーマ / ウィンドウ配置",
        RepairCategory.PLUGINS: "プラグイン / 権限 / プラグイン障害",
        RepairCategory.CAPTURE_STACK: "パケットキャプチャ / tshark / dumpcap / プロセス監視",
        RepairCategory.PERMISSIONS_PATHS: "パス / 権限 / 書き込み",
        RepairCategory.CACHE_TEMP: "キャッシュ / 一時ファイル / 残留状態",
        RepairCategory.SERVER_RUNTIME: "ローカルサービス / ポート / ランタイム",
        RepairCategory.PERFORMANCE_MOTION: "アニメーション / 描画 / 性能",
        RepairCategory.FEATURE_INTEGRATION: "高度な機能 / モジュール接続 / 完全性",
        RepairCategory.RUNTIME_STATE: "実行状態 / 中断タスク / 再開チェックポイント",
        RepairCategory.OTHER: "その他 / 不明な問題",
    },
    "ko_KR": {
        RepairCategory.ENCODING_UI: "문자 깨짐 / 언어 / 글꼴 표시",
        RepairCategory.STARTUP_CRASH: "시작 실패 / 충돌 / 충돌 반복",
        RepairCategory.PROGRAM_FILES: "프로그램 파일 누락 / 손상",
        RepairCategory.DEPENDENCIES: "Python / Qt / 모듈 의존성",
        RepairCategory.DATABASE_INDEX: "데이터베이스 / FTS / WAL",
        RepairCategory.SETTINGS_UI: "설정 / 테마 / 창 레이아웃",
        RepairCategory.PLUGINS: "플러그인 / 권한 / 플러그인 충돌",
        RepairCategory.CAPTURE_STACK: "패킷 캡처 / tshark / dumpcap / 프로세스 모니터",
        RepairCategory.PERMISSIONS_PATHS: "경로 / 권한 / 쓰기 접근",
        RepairCategory.CACHE_TEMP: "캐시 / 임시 파일 / 잔여 상태",
        RepairCategory.SERVER_RUNTIME: "로컬 서비스 / 포트 / 런타임",
        RepairCategory.PERFORMANCE_MOTION: "애니메이션 / 렌더링 / 성능",
        RepairCategory.FEATURE_INTEGRATION: "고급 기능 / 모듈 연결 / 기능 무결성",
        RepairCategory.RUNTIME_STATE: "실행 상태 / 중단 작업 / 복구 체크포인트",
        RepairCategory.OTHER: "기타 / 알 수 없는 문제",
    },
    "ar_SA": {
        RepairCategory.ENCODING_UI: "تشوه النص / اللغة / عرض الخط",
        RepairCategory.STARTUP_CRASH: "فشل البدء / انهيار / حلقة انهيار",
        RepairCategory.PROGRAM_FILES: "ملفات برنامج مفقودة أو تالفة",
        RepairCategory.DEPENDENCIES: "اعتماديات Python / Qt / الوحدات",
        RepairCategory.DATABASE_INDEX: "قاعدة البيانات / فهرس FTS / WAL",
        RepairCategory.SETTINGS_UI: "الإعدادات / السمة / تخطيط النافذة",
        RepairCategory.PLUGINS: "الإضافات / الأذونات / أعطال الإضافات",
        RepairCategory.CAPTURE_STACK: "التقاط الحزم / tshark / dumpcap / مراقبة العمليات",
        RepairCategory.PERMISSIONS_PATHS: "المسارات / الأذونات / الكتابة",
        RepairCategory.CACHE_TEMP: "الذاكرة المؤقتة / الملفات المؤقتة / الحالة المتبقية",
        RepairCategory.SERVER_RUNTIME: "الخدمة المحلية / المنفذ / بيئة التشغيل",
        RepairCategory.PERFORMANCE_MOTION: "الحركة / العرض / الأداء",
        RepairCategory.FEATURE_INTEGRATION: "الميزات المتقدمة / ربط الوحدات / سلامة القدرات",
        RepairCategory.RUNTIME_STATE: "حالة التشغيل / المهام المتوقفة / نقاط الاستعادة",
        RepairCategory.OTHER: "أخرى / مشكلة غير معروفة",
    },
    "la_VA": {
        RepairCategory.ENCODING_UI: "Textus corruptus / lingua / fontes",
        RepairCategory.STARTUP_CRASH: "Defectus initii / collapsus / iter collapsuum",
        RepairCategory.PROGRAM_FILES: "Fasciculi programmatis desunt vel corrupti sunt",
        RepairCategory.DEPENDENCIES: "Dependentiae Python / Qt / modulorum",
        RepairCategory.DATABASE_INDEX: "Database / index FTS / WAL",
        RepairCategory.SETTINGS_UI: "Configurationes / thema / dispositio fenestrae",
        RepairCategory.PLUGINS: "Additamenta / permissiones / errores",
        RepairCategory.CAPTURE_STACK: "Captura fasciculorum / tshark / dumpcap / processus",
        RepairCategory.PERMISSIONS_PATHS: "Viae / permissiones / scriptura",
        RepairCategory.CACHE_TEMP: "Cache / fasciculi temporarii / status residuus",
        RepairCategory.SERVER_RUNTIME: "Servitium locale / porta / runtime",
        RepairCategory.PERFORMANCE_MOTION: "Motus / render / efficientia",
        RepairCategory.FEATURE_INTEGRATION: "Facultates provectae / nexus modulorum",
        RepairCategory.RUNTIME_STATE: "Status runtime / opera interrupta / puncta restitutionis",
        RepairCategory.OTHER: "Aliud / problema incertum",
    },
}


def _t(locale: str, key: str) -> str:
    table = _TEXT.get(locale) or _TEXT["en_US"]
    return table.get(key, _TEXT["en_US"].get(key, key))


def _category_label(locale: str, category: RepairCategory) -> str:
    if locale in {"zh_CN", "zh_TW"}:
        source = CATEGORY_LABELS[category]
        if locale == "zh_TW":
            return source.replace("乱码", "亂碼").replace("异常", "異常").replace("损坏", "損壞").replace("设置", "設定").replace("权限", "權限").replace("缓存", "快取").replace("运行", "執行")
        return source
    table = _CATEGORY_NATIVE.get(locale) or _CATEGORY_NATIVE["en_US"]
    return table.get(category, _CATEGORY_NATIVE["en_US"].get(category, category.value))


def _finding_text(locale: str, finding) -> str:
    severity = str(finding.severity or "info").upper()
    evidence = str(finding.evidence or "").strip()
    parts = [
        f"[{severity}] {finding.title}",
        f"{_category_label(locale, finding.category)} · {finding.code}",
        f"{_t(locale, 'fingerprint')}: {finding.fingerprint}",
        str(finding.detail or ""),
    ]
    if evidence:
        parts.append(f"{_t(locale, 'evidence')}: {evidence}")
    return "\n".join(part for part in parts if part)


def ask_startup_repair(report: HealthReport, locale: str, parent: QWidget | None = None) -> bool:
    message = QMessageBox(parent)
    message.setIcon(QMessageBox.Icon.Warning)
    message.setWindowTitle(_t(locale, "prompt_title"))
    message.setText(_t(locale, "prompt"))
    message.setInformativeText(_t(locale, "prompt_detail").format(count=len(report.findings)))
    details = "\n\n".join(_finding_text(locale, item) for item in report.findings[:20])
    if len(report.findings) > 20:
        details += "\n\n… " + _t(locale, "more_issues").format(count=len(report.findings) - 20)
    if details:
        message.setDetailedText(details)
    message.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
    message.setDefaultButton(QMessageBox.StandardButton.Yes)
    return message.exec() == QMessageBox.StandardButton.Yes


class RepairSelectionDialog(QDialog):
    def __init__(self, report: HealthReport, locale: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.report = report
        self.locale = locale
        self.setWindowTitle(_t(locale, "title"))
        self.resize(760, 680)
        layout = QVBoxLayout(self)
        title = QLabel(_t(locale, "title"))
        title.setStyleSheet("font-size: 22px; font-weight: 700;")
        layout.addWidget(title)
        flow = QLabel(_t(locale, "workflow"))
        flow.setWordWrap(True)
        layout.addWidget(flow)
        safety = QLabel(_t(locale, "safety"))
        safety.setWordWrap(True)
        safety.setStyleSheet("font-weight: 600;")
        layout.addWidget(safety)

        self.auto_radio = QRadioButton(_t(locale, "auto"))
        self.manual_radio = QRadioButton(_t(locale, "manual"))
        self.auto_radio.setChecked(True)
        self.mode_group = QButtonGroup(self)
        self.mode_group.setExclusive(True)
        self.mode_group.addButton(self.auto_radio)
        self.mode_group.addButton(self.manual_radio)
        layout.addWidget(self.auto_radio)
        hint = QLabel(_t(locale, "auto_hint"))
        hint.setWordWrap(True)
        hint.setContentsMargins(24, 0, 0, 4)
        layout.addWidget(hint)
        layout.addWidget(self.manual_radio)

        detected_box = QGroupBox(_t(locale, "detected"))
        detected_layout = QVBoxLayout(detected_box)
        critical = sum(1 for item in report.findings if str(item.severity).casefold() == "critical")
        warning = sum(1 for item in report.findings if str(item.severity).casefold() == "warning")
        summary = QLabel(_t(locale, "issues_summary").format(count=len(report.findings), critical=critical, warning=warning))
        summary.setProperty("repairSummary", True)
        detected_layout.addWidget(summary)
        self.finding_details = QPlainTextEdit()
        self.finding_details.setReadOnly(True)
        self.finding_details.setMaximumBlockCount(1200)
        self.finding_details.setMinimumHeight(190)
        self.finding_details.setPlainText(
            "\n\n────────────────────────\n\n".join(_finding_text(locale, item) for item in report.findings)
            if report.findings
            else _t(locale, "none")
        )
        detected_layout.addWidget(self.finding_details, 1)
        layout.addWidget(detected_box, 1)

        types_box = QGroupBox(_t(locale, "types"))
        types_layout = QGridLayout(types_box)
        self.checkboxes: dict[RepairCategory, QCheckBox] = {}
        detected = set(report.categories)
        for index, category in enumerate(RepairCategory):
            checkbox = QCheckBox(_category_label(locale, category))
            checkbox.setChecked(category in detected)
            checkbox.setEnabled(False)
            self.checkboxes[category] = checkbox
            types_layout.addWidget(checkbox, index // 2, index % 2)
        layout.addWidget(types_box)

        def update_manual(enabled: bool) -> None:
            for checkbox in self.checkboxes.values():
                checkbox.setEnabled(enabled)
        self.manual_radio.toggled.connect(update_manual)

        buttons = QDialogButtonBox()
                                                                                      
                                                                                       
                                                                                          
                                                                                           
                                 
        start = QPushButton(_t(locale, "start"), buttons)
        cancel = QPushButton(_t(locale, "cancel"), buttons)
        start.setDefault(True)
        start.setAutoDefault(True)
        buttons.addButton(start, QDialogButtonBox.ButtonRole.AcceptRole)
        buttons.addButton(cancel, QDialogButtonBox.ButtonRole.RejectRole)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def selected_categories(self) -> list[RepairCategory]:
        if self.auto_radio.isChecked():
            return self.report.categories or [RepairCategory.OTHER]
        selected = [category for category, checkbox in self.checkboxes.items() if checkbox.isChecked()]
        return selected or [RepairCategory.OTHER]


def show_post_repair_report(report_path: Path, locale: str, parent: QWidget | None = None) -> None:
    if not report_path.exists():
        return
    try:
        report = json.loads(read_text_limited(report_path, 4 * 1024 * 1024, encoding="utf-8"))
    except (OSError, ValueError):
        return
    if not isinstance(report, dict):
        return
    success = bool(report.get("success"))
    message = QMessageBox(parent)
    message.setWindowTitle(_t(locale, "report"))
    message.setIcon(QMessageBox.Icon.Information if success else QMessageBox.Icon.Warning)
    message.setText(_t(locale, "post_ok" if success else "post_partial"))
    actions = report.get("actions", [])
    unresolved = report.get("unresolved", [])
    if not isinstance(actions, list):
        actions = []
    if not isinstance(unresolved, list):
        unresolved = []
    details = [
        f"{str(item.get('status', '?')).upper()} · {item.get('action', '')}: {item.get('detail', '')}"
        for item in actions if isinstance(item, dict)
    ]
    if unresolved:
        details.append("\nUnresolved:")
        details.extend(f"• {item}" for item in unresolved)
    details.append(f"\nBackup: {report.get('backup_dir', '')}")
    message.setDetailedText("\n".join(details))
    message.exec()
