import AppKit
import SwiftUI
import ServiceManagement
import UserNotifications
import AVFoundation

// MARK: - モデル

struct Finding: Codable, Identifiable {
    let id: String
    let title: String
    let status: String
    let statusJa: String
    let detail: String
    let weight: Int
    let tier: String
    let tierJa: String
    let how: String?

    enum CodingKeys: String, CodingKey {
        case id, title, status, detail, weight, tier, how
        case statusJa = "status_ja"
        case tierJa = "tier_ja"
    }

    var isOK: Bool { status == "ok" }
    var isWeak: Bool { status == "weak" }
    var isAck: Bool { status == "ack" }
    var isUnknown: Bool { status == "unknown" }

    /// 一般ユーザー向けの重要度ラベル（重みを日本語化）。
    var importanceJa: String {
        switch weight {
        case 6...: return "重要度: 高"
        case 4...5: return "重要度: 中"
        default: return "重要度: 低"
        }
    }
}

struct TopAction: Codable, Identifiable {
    let id: String
    let title: String
    let detail: String
    let weight: Int
    let tier: String
    let tierJa: String
    let how: String

    enum CodingKeys: String, CodingKey {
        case id, title, detail, weight, tier, how
        case tierJa = "tier_ja"
    }
}

struct TrendPoint: Codable, Identifiable {
    let date: String
    let score: Int?
    var id: String { date }
}

struct Counts: Codable {
    let ok: Int
    let weak: Int
    let ack: Int?
    let total: Int
}

struct AttackItem: Codable, Identifiable {
    let typeJa: String
    let pattern: String
    let count: Int
    var id: String { pattern }

    enum CodingKeys: String, CodingKey {
        case pattern, count
        case typeJa = "type_ja"
    }
}

struct Attacks: Codable {
    let totalObservations: Int
    let totalAttempts: Int
    let byType: [String: Int]
    let top: [AttackItem]

    enum CodingKeys: String, CodingKey {
        case top
        case totalObservations = "total_observations"
        case totalAttempts = "total_attempts"
        case byType = "by_type"
    }
}

struct Status: Codable {
    let updated: String
    let date: String
    let host: String
    let os: String
    let osVersion: String
    let admin: Bool
    let intel: String
    let score: Int?
    let prevScore: Int?
    let delta: Int?
    let grade: String
    let counts: Counts
    let trend: [TrendPoint]
    let findings: [Finding]
    let topActions: [TopAction]
    let historyDays: Int
    let fixedToday: Int?
    let attacks: Attacks?

    enum CodingKeys: String, CodingKey {
        case updated, date, host, os, admin, intel, score, delta, grade, counts, trend, findings, attacks
        case osVersion = "os_version"
        case prevScore = "prev_score"
        case topActions = "top_actions"
        case historyDays = "history_days"
        case fixedToday = "fixed_today"
    }

    var scoreValue: Int { score ?? 0 }
}

// MARK: - 読み込み

enum Store {
    static var statusPath: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".mamori/status.json")
    }

    /// daily.py を探す。ダウンロードした .app でも動くよう、同梱 Resources を最優先。
    /// 1. 環境変数 MAMORI_DAILY
    /// 2. .app の Resources/agent/daily.py（同梱）
    /// 3. ~/.mamori/kit/mamori/agent/daily.py（install.sh が入れたキット）
    /// 4. ~/workspace/mamori/agent/daily.py（開発時）
    static var dailyPath: URL? {
        var candidates: [URL] = []
        if let env = ProcessInfo.processInfo.environment["MAMORI_DAILY"], !env.isEmpty {
            candidates.append(URL(fileURLWithPath: env))
        }
        if let res = Bundle.main.resourceURL {
            candidates.append(res.appendingPathComponent("agent/daily.py"))
        }
        let home = FileManager.default.homeDirectoryForCurrentUser
        candidates.append(home.appendingPathComponent(".mamori/kit/mamori/agent/daily.py"))
        candidates.append(home.appendingPathComponent("workspace/mamori/agent/daily.py"))
        return candidates.first { FileManager.default.fileExists(atPath: $0.path) }
    }

    /// python3 を探す。存在するだけでなく「実際に起動できて 3.9 以上」を確認する。
    /// Command Line Tools 未導入の /usr/bin/python3 は Apple のインストーラを出す
    /// だけのシミなので、存在チェックでは掴めない。ここで起動検証して弾く。
    /// ただし検出のためだけにシミを起動するとインストーラのダイアログが勝手に出るので、
    /// /usr/bin/python3 は CLT 導入済みのときだけ試す。
    static func pythonPath() -> String? {
        // まず Homebrew / /usr/local の本物の python3（ダイアログを出さない）
        for path in ["/opt/homebrew/bin/python3", "/usr/local/bin/python3"]
        where FileManager.default.isExecutableFile(atPath: path) {
            if pythonWorks(path) { return path }
        }
        // /usr/bin/python3 は CLT があるときだけ（無いとシミがダイアログを出す）
        if hasCommandLineTools,
           FileManager.default.isExecutableFile(atPath: "/usr/bin/python3"),
           pythonWorks("/usr/bin/python3") {
            return "/usr/bin/python3"
        }
        return nil
    }

    /// その python3 が実際に 3.9 以上で動くか（タイムアウト付き）。
    static func pythonWorks(_ path: String) -> Bool {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        p.arguments = ["-c", "import sys; sys.exit(0 if sys.version_info >= (3,9) else 1)"]
        p.standardOutput = Pipe()
        p.standardError = Pipe()
        // シミがインストーラを出すケースで固まらないよう環境を素に保つ
        var env = ProcessInfo.processInfo.environment
        env.removeValue(forKey: "PYTHONHOME")
        env.removeValue(forKey: "PYTHONPATH")
        p.environment = env
        do {
            try p.run()
        } catch {
            return false
        }
        // 最大5秒待つ。応答しなければ（＝シミ）ダメとみなす。
        let deadline = Date().addingTimeInterval(5)
        while p.isRunning && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.05)
        }
        if p.isRunning {
            p.terminate()
            return false
        }
        return p.terminationStatus == 0
    }

    /// Command Line Tools が入っているか（python3 が無いときの案内分岐に使う）。
    static var hasCommandLineTools: Bool {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/xcode-select")
        p.arguments = ["-p"]
        p.standardOutput = Pipe()
        p.standardError = Pipe()
        do { try p.run() } catch { return false }
        p.waitUntilExit()
        return p.terminationStatus == 0
    }

    /// Apple の Command Line Tools インストーラを起動する（GUI ダイアログが出る）。
    static func installCommandLineTools() {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/xcode-select")
        p.arguments = ["--install"]
        p.standardOutput = Pipe()
        p.standardError = Pipe()
        try? p.run()
    }

    /// mamori_guard.py を探す（daily.py と同じ探索順）。
    static var guardPath: URL? {
        var candidates: [URL] = []
        if let env = ProcessInfo.processInfo.environment["MAMORI_GUARD"], !env.isEmpty {
            candidates.append(URL(fileURLWithPath: env))
        }
        if let res = Bundle.main.resourceURL {
            candidates.append(res.appendingPathComponent("agent/mamori_guard.py"))
        }
        let home = FileManager.default.homeDirectoryForCurrentUser
        candidates.append(home.appendingPathComponent(".mamori/kit/mamori/agent/mamori_guard.py"))
        candidates.append(home.appendingPathComponent("workspace/mamori/agent/mamori_guard.py"))
        return candidates.first { FileManager.default.fileExists(atPath: $0.path) }
    }

    /// 同梱エンジンを ~/.mamori/ へ同期し、launchd（毎日の点検）と
    /// アプリが同じ版の daily.py / guard / attacks を使うようにする。
    static func syncBundledEngine() {
        guard let res = Bundle.main.resourceURL else { return }
        let src = res.appendingPathComponent("agent")
        let home = FileManager.default.homeDirectoryForCurrentUser
        let dst = home.appendingPathComponent(".mamori")
        let fm = FileManager.default
        guard fm.fileExists(atPath: src.path) else { return }
        try? fm.createDirectory(at: dst, withIntermediateDirectories: true)

        // 版数ガード：同梱の版が既存より新しくない時は上書きしない（降格防止）。
        let verPath = dst.appendingPathComponent("engine.version")
        let bundledVer = (Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String) ?? "0"
        let existingVer = (try? String(contentsOf: verPath, encoding: .utf8))?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? "0"
        func verNum(_ v: String) -> [Int] {
            v.split(separator: ".").map { Int($0) ?? 0 }
        }
        func isNewer(_ a: String, _ b: String) -> Bool {
            let x = verNum(a), y = verNum(b)
            for i in 0..<max(x.count, y.count) {
                let p = i < x.count ? x[i] : 0
                let q = i < y.count ? y[i] : 0
                if p != q { return p > q }
            }
            return false
        }
        // 降格防止：同梱が既存より古い時だけ書かない。同版・新版は内容差分があれば書く
        // （開発中に版を上げ忘れても同期される）。
        let downgrade = isNewer(existingVer, bundledVer)
        for f in ["daily.py", "mamori_guard.py", "attacks.py"] {
            let from = src.appendingPathComponent(f)
            let to = dst.appendingPathComponent(f)
            guard let data = try? Data(contentsOf: from) else { continue }
            let existing = try? Data(contentsOf: to)
            if data == existing { continue }
            guard !downgrade else { continue }
            // 一時ファイル経由で原子的に置換する。残骸があっても失敗しないよう先に消す。
            let tmp = dst.appendingPathComponent(".\(f).tmp")
            try? fm.removeItem(at: tmp)
            if (try? data.write(to: tmp, options: .atomic)) != nil {
                _ = try? fm.replaceItemAt(to, withItemAt: tmp)
            }
        }
        if !downgrade { try? bundledVer.write(to: verPath, atomically: true, encoding: .utf8) }
    }

    static func load() -> Status? {
        guard let data = try? Data(contentsOf: statusPath) else { return nil }
        return try? JSONDecoder().decode(Status.self, from: data)
    }

    /// 読み取り結果を区別して返す（破損・スキーマ変更を握り潰さない）。
    enum LoadResult {
        case ok(Status)
        case missing
        case broken
    }
    static func loadResult() -> LoadResult {
        guard FileManager.default.fileExists(atPath: statusPath.path) else { return .missing }
        guard let data = try? Data(contentsOf: statusPath),
              let s = try? JSONDecoder().decode(Status.self, from: data) else { return .broken }
        return .ok(s)
    }

    static func hasStatus() -> Bool {
        FileManager.default.fileExists(atPath: statusPath.path)
    }

    /// 手動対応済みの記録（ack）。項目ID→記録日（yyyy-MM-dd）を保持する。
    /// 「対応した」は当日ぶん表示を静めるだけで、点数は水増ししない。
    static var ackPath: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".mamori/acknowledged.json")
    }
    static func loadAck() -> [String: String] {
        guard let data = try? Data(contentsOf: ackPath),
              let obj = try? JSONSerialization.jsonObject(with: data) else { return [:] }
        if let dict = obj as? [String: String] { return dict }
        if let arr = obj as? [String] {  // 旧形式（日付なし）
            let f = DateFormatter(); f.dateFormat = "yyyy-MM-dd"
            let today = f.string(from: Date())
            return Dictionary(uniqueKeysWithValues: arr.map { ($0, today) })
        }
        return [:]
    }
    static func ack(_ id: String) {
        var dict = loadAck()
        let f = DateFormatter(); f.dateFormat = "yyyy-MM-dd"
        dict[id] = f.string(from: Date())
        if let data = try? JSONSerialization.data(withJSONObject: dict, options: [.prettyPrinted]) {
            try? data.write(to: ackPath)
        }
    }

    /// 点検を今すぐ実行する（daily.py --fix）。重いのでバックグラウンドで。
    /// 同時に2つ走ると state ファイルが壊れるので、実行中は新規起動せず、
    /// 進行中の結果を待っている呼び出し元へ配る。
    private static let running = NSLock()
    private static var isRunning = false
    private static var waiters: [(Bool) -> Void] = []
    static func refresh(completion: @escaping (Bool) -> Void) {
        running.lock()
        if isRunning {
            waiters.append(completion)
            running.unlock()
            return
        }
        isRunning = true
        running.unlock()

        func finish(_ ok: Bool) {
            running.lock()
            isRunning = false
            let ws = waiters
            waiters.removeAll()
            running.unlock()
            DispatchQueue.main.async {
                completion(ok)
                ws.forEach { $0(ok) }
            }
        }
        guard let daily = dailyPath, let py = pythonPath() else {
            finish(false); return
        }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: py)
        p.arguments = [daily.path, "--fix", "--quiet"]
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        p.terminationHandler = { proc in
            finish(proc.terminationStatus == 0)
        }
        do { try p.run() } catch { finish(false); return }
        // 300秒で打ち切る（softwareupdate 等でハングしても UI が固まらないように）。
        DispatchQueue.global().asyncAfter(deadline: .now() + 300) {
            if p.isRunning { p.terminate() }
        }
    }

    /// 指定した項目だけを直す（guard fix --approve <id>）。承認済みの操作だけ呼ぶ。
    /// 管理者権限が要る場合は osascript で macOS 標準のパスワードダイアログを出す。
    /// 戻り: (成功, メッセージ, 管理者権限が必要だったか)
    static func fixItem(_ id: String, completion: @escaping (Bool, String, Bool) -> Void) {
        guard let guardPy = guardPath, let py = pythonPath() else {
            completion(false, "点検エンジンが見つかりません", false); return
        }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: py)
        p.arguments = [guardPy.path, "fix", "--approve", id, "--json"]
        let out = Pipe()
        p.standardOutput = out
        p.standardError = FileHandle.nullDevice
        var finished = false
        p.terminationHandler = { proc in
            guard !finished else { return }
            finished = true
            let data = out.fileHandleForReading.readDataToEndOfFile()
            let text = String(data: data, encoding: .utf8) ?? ""
            var results: [(String, String)] = []
            if let d = text.data(using: .utf8),
               let obj = try? JSONSerialization.jsonObject(with: d) as? [String: Any],
               let applied = obj["applied"] as? [[String: Any]] {
                results = applied.map { ("\($0["id"] ?? "")", "\($0["result"] ?? "")") }
            }
            let needsAdmin = results.contains { $0.1 == "needs-admin" }
            let fixedCount = results.filter { $0.1 == "fixed" }.count
            let msg = results.map { "\($0.0): \(humanResult($0.1))" }.joined(separator: "、")
            DispatchQueue.main.async {
                completion(proc.terminationStatus == 0 && fixedCount > 0, msg, needsAdmin)
            }
        }
        do { try p.run() } catch { completion(false, "実行できませんでした", false); return }
        DispatchQueue.global().asyncAfter(deadline: .now() + 300) {
            if p.isRunning { p.terminate() }
        }
    }

    /// 管理者権限が必要な項目を、macOS 標準ダイアログ経由で直す。
    /// パスはシェル単一引用符で保護し、結果の JSON を検証してから成功を返す。
    static func fixItemAsAdmin(_ id: String, completion: @escaping (Bool, String) -> Void) {
        guard let guardPy = guardPath, let py = pythonPath() else {
            completion(false, "点検エンジンが見つかりません"); return
        }
        func shq(_ s: String) -> String {
            return "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
        }
        let inner = "\(shq(py)) \(shq(guardPy.path)) fix --approve \(shq(id)) --json"
        let escaped = inner.replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        let script = "do shell script \"\(escaped)\" with administrator privileges"
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        p.arguments = ["-e", script]
        let out = Pipe()
        p.standardOutput = out
        p.standardError = FileHandle.nullDevice
        p.terminationHandler = { proc in
            let data = out.fileHandleForReading.readDataToEndOfFile()
            let text = String(data: data, encoding: .utf8) ?? ""
            var fixed = false
            var applied: [(String, String)] = []
            if let d = text.data(using: .utf8),
               let obj = try? JSONSerialization.jsonObject(with: d) as? [String: Any],
               let arr = obj["applied"] as? [[String: Any]] {
                applied = arr.map { ("\($0["id"] ?? "")", "\($0["result"] ?? "")") }
                fixed = applied.contains { $0.1 == "fixed" }
            }
            let msg = applied.isEmpty ? "" : applied.map { humanResult($0.1) }.joined(separator: "、")
            DispatchQueue.main.async {
                if proc.terminationStatus != 0 {
                    completion(false, "管理者の許可が必要でした（キャンセルした場合は変更されていません）")
                } else if fixed {
                    completion(true, msg.isEmpty ? "直しました" : msg)
                } else {
                    completion(false, msg.isEmpty ? "直りませんでした" : msg)
                }
            }
        }
        do { try p.run() } catch { completion(false, "実行できませんでした") }
    }

    static func humanResult(_ r: String) -> String {
        switch r {
        case "fixed": return "直しました"
        case "needs-admin": return "管理者の許可が必要です"
        case "failed": return "失敗しました"
        case "no-undo": return "更新済み（元に戻せません）"
        case "dry-run": return "試行のみ"
        case "rolled-back": return "元に戻しました"
        default: return r
        }
    }
}

// MARK: - 色

extension Color {
    static func forScore(_ s: Int) -> Color {
        switch s {
        case 90...: return Color(red: 0.18, green: 0.72, blue: 0.42)
        case 75..<90: return Color(red: 0.35, green: 0.70, blue: 0.35)
        case 60..<75: return Color(red: 0.90, green: 0.70, blue: 0.20)
        case 40..<60: return Color(red: 0.93, green: 0.55, blue: 0.18)
        default: return Color(red: 0.88, green: 0.30, blue: 0.28)
        }
    }
}

// MARK: - スパークライン

struct Sparkline: View {
    let points: [TrendPoint]
    var body: some View {
        GeometryReader { geo in
            let vals = points.compactMap { $0.score }
            let lo = max(0, (vals.min() ?? 0) - 5)
            let hi = min(100, (vals.max() ?? 100) + 5)
            let span = max(1, hi - lo)
            let w = geo.size.width
            let h = geo.size.height
            let step = vals.count > 1 ? w / CGFloat(vals.count - 1) : w
            Path { p in
                for (i, v) in vals.enumerated() {
                    let x = CGFloat(i) * step
                    let y = h - (CGFloat(v - lo) / CGFloat(span)) * h
                    if i == 0 { p.move(to: CGPoint(x: x, y: y)) }
                    else { p.addLine(to: CGPoint(x: x, y: y)) }
                }
            }
            .stroke(Color.forScore(vals.last ?? 0), style: StrokeStyle(lineWidth: 2, lineCap: .round, lineJoin: .round))
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(sparklineLabel)
    }

    private var sparklineLabel: String {
        let vals = points.compactMap { $0.score }
        guard let first = vals.first, let last = vals.last else { return "点数の推移なし" }
        if first == last { return "点数の推移 \(first)点で横ばい" }
        return "点数の推移 \(first)点から\(last)点"
    }
}

// MARK: - ポップオーバー

struct Panel: View {
    @State private var status: Status?
    @State private var busy = false
    @State private var fixingId: String?
    @State private var markingId: String?
    @State private var lastError: String?
    @State private var notice: String?
    @State private var loadBroken = false
    @State private var acked: [String: String] = [:]
    @State private var loginError: String?
    @State private var notifyDenied = false
    @State private var speakEnabled = Speaker.enabled
    // nil=確認中, true=点検できる, false=Python が無い等で準備が必要
    @State private var engineReady: Bool?
    @State private var needsCommandLineTools = false
    @State private var installing = false

    static var todayStr: String {
        let f = DateFormatter(); f.dateFormat = "yyyy-MM-dd"
        return f.string(from: Date())
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()
            if let s = status {
                ScrollView {
                    VStack(alignment: .leading, spacing: 14) {
                        trendCard(s)
                        actionsCard(s)
                        attacksCard(s)
                        checksCard(s)
                        footer(s)
                    }
                    .padding(14)
                }
                .frame(maxHeight: 480)
            } else {
                VStack(spacing: 12) {
                    if busy {
                        ProgressView()
                        Text("この Mac の守りを点検しています…").font(.callout).foregroundStyle(.secondary)
                        Text("初回は1〜2分かかることがあります。").font(.caption).foregroundStyle(.tertiary)
                    } else if loadBroken {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .font(.largeTitle).foregroundStyle(.orange)
                        Text("記録を読み取れませんでした").font(.callout).foregroundStyle(.secondary)
                        Button { runNow() } label: {
                            Label("もう一度点検する", systemImage: "arrow.clockwise")
                        }.buttonStyle(.borderedProminent)
                    } else if engineReady == nil {
                        ProgressView()
                        Text("準備を確認しています…").font(.caption).foregroundStyle(.secondary)
                    } else if engineReady == false {
                        if Store.dailyPath == nil {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .font(.largeTitle).foregroundStyle(.orange)
                            Text("点検エンジンが見つかりません").font(.callout).foregroundStyle(.secondary)
                            Text("アプリを Applications フォルダに置いた状態で開き直してください。")
                                .font(.caption).foregroundStyle(.tertiary)
                                .multilineTextAlignment(.center)
                        } else if needsCommandLineTools {
                            Image(systemName: "wrench.and.screwdriver.fill")
                                .font(.largeTitle).foregroundStyle(.orange)
                            Text("あと1ステップで使えます").font(.callout).foregroundStyle(.secondary)
                            Text("点検には Apple の「コマンドラインデベロッパツール」が必要です。下のボタンでインストールできます（無料・数分）。")
                                .font(.caption).foregroundStyle(.tertiary)
                                .multilineTextAlignment(.center)
                            Button {
                                installTools()
                            } label: {
                                Label(installing ? "インストール中…" : "開発者ツールを入れる", systemImage: "arrow.down.circle")
                            }
                            .buttonStyle(.borderedProminent)
                            .disabled(installing)
                            Text("インストール後、この画面の「再確認」を押してください。")
                                .font(.caption2).foregroundStyle(.tertiary)
                            Button("再確認") { checkEngine() }
                                .buttonStyle(.borderless)
                        } else {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .font(.largeTitle).foregroundStyle(.orange)
                            Text("点検エンジンを起動できません").font(.callout).foregroundStyle(.secondary)
                            Text("Python 3.9 以上が見つかりませんでした。ターミナルで `xcode-select --install` を実行するか、下のボタンをお試しください。")
                                .font(.caption).foregroundStyle(.tertiary)
                                .multilineTextAlignment(.center)
                            Button {
                                installTools()
                            } label: {
                                Label("開発者ツールを入れる", systemImage: "arrow.down.circle")
                            }
                            .buttonStyle(.bordered)
                            .disabled(installing)
                            Button("再確認") { checkEngine() }
                                .buttonStyle(.borderless)
                        }
                    } else {
                        Image(systemName: "shield.lefthalf.filled")
                            .font(.system(size: 40)).foregroundStyle(Color.forScore(60))
                        Text("まだ点検していません").font(.callout).foregroundStyle(.secondary)
                        Button {
                            runNow()
                        } label: {
                            Label("今すぐ点検する", systemImage: "arrow.clockwise")
                        }
                        .buttonStyle(.borderedProminent)
                        Text("この Mac の設定を読み取り、安全に直せるものは自動で直します。")
                            .font(.caption).foregroundStyle(.tertiary)
                            .multilineTextAlignment(.center)
                    }
                    if let e = lastError {
                        Text(e).font(.caption).foregroundStyle(.red).multilineTextAlignment(.center)
                    }
                }
                .padding(20)
                .frame(maxWidth: .infinity, minHeight: 160)
            }
        }
        .frame(width: 400)
        .onAppear {
            reload()
            Notifier.checkAuthorization { ok in notifyDenied = !ok }
            checkEngine()
        }
    }

    /// エンジン（daily.py + 動く python3）が揃っているか確認し、揃っていれば初回点検を開始。
    private func checkEngine() {
        engineReady = nil
        DispatchQueue.global(qos: .userInitiated).async {
            let hasDaily = Store.dailyPath != nil
            let py = Store.pythonPath()
            let clt = Store.hasCommandLineTools
            DispatchQueue.main.async {
                engineReady = hasDaily && (py != nil)
                needsCommandLineTools = (py == nil) && !clt
                if engineReady == true, status == nil, !busy {
                    runNow()
                }
            }
        }
    }

    private func installTools() {
        installing = true
        Store.installCommandLineTools()
        // Apple のインストーラは GUI で進む。数秒後に自動で再確認し、以後も
        // ユーザーが「再確認」を押せるようにしておく。
        DispatchQueue.main.asyncAfter(deadline: .now() + 8) {
            installing = false
            checkEngine()
        }
    }

    private var header: some View {
        HStack(alignment: .center, spacing: 12) {
            ZStack {
                Circle().fill(headerColor.opacity(0.15)).frame(width: 56, height: 56)
                Text(status.map { "\($0.scoreValue)" } ?? "–")
                    .font(.system(size: 24, weight: .bold, design: .rounded))
                    .foregroundStyle(headerColor)
            }
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(status.map { "守りの点数 \($0.scoreValue)点、\($0.grade)" } ?? "守りの点数 未記録")
            VStack(alignment: .leading, spacing: 2) {
                Text("守りの点数").font(.headline).accessibilityHidden(true)
                if let s = status {
                    HStack(spacing: 6) {
                        Text(s.grade).font(.subheadline).foregroundStyle(.secondary)
                            .accessibilityHidden(true)
                        if let d = s.delta, d != 0 {
                            Text(d > 0 ? "+\(d)" : "\(d)")
                                .font(.caption.bold())
                                .padding(.horizontal, 6).padding(.vertical, 1)
                                .background((d > 0 ? Color.green : Color.red).opacity(0.15))
                                .foregroundStyle(d > 0 ? .green : .red)
                                .clipShape(Capsule())
                        }
                    }
                    Text("\(s.counts.total)項目の重要度つき平均です").font(.caption2).foregroundStyle(.tertiary)
                } else {
                    Text("未記録").font(.subheadline).foregroundStyle(.secondary)
                }
            }
            Spacer()
            if let s = status {
                Button {
                    Speaker.say(Speaker.summary(s))
                } label: {
                    Image(systemName: "speaker.wave.2.fill")
                }
                .buttonStyle(.borderless)
                .help("いまの状態を読み上げる")
            }
            Button {
                runNow()
            } label: {
                if busy { ProgressView().controlSize(.small) }
                else { Image(systemName: "arrow.clockwise") }
            }
            .buttonStyle(.borderless)
            .help("今すぐ点検して、直せるものは自動で直す")
            .disabled(busy || fixingId != nil)
        }
        .padding(14)
    }

    private var headerColor: Color {
        guard let s = status else { return .secondary }
        return Color.forScore(s.scoreValue)
    }

    private func trendCard(_ s: Status) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text("この7日").font(.caption.bold()).foregroundStyle(.secondary)
                Spacer()
                if let d = s.delta, d != 0 {
                    Text(d > 0 ? "改善 ↑\(d)" : "悪化 ↓\(-d)")
                        .font(.caption).foregroundStyle(d > 0 ? .green : .red)
                }
            }
            Sparkline(points: s.trend).frame(height: 40)
            HStack {
                Text(s.trend.first?.date ?? "").font(.caption2).foregroundStyle(.tertiary)
                Spacer()
                Text(s.trend.last?.date ?? "").font(.caption2).foregroundStyle(.tertiary)
            }
        }
        .padding(10)
        .background(Color.primary.opacity(0.04))
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }

    private func actionsCard(_ s: Status) -> some View {
        let visible = s.topActions.filter { acked[$0.id] != Self.todayStr }
        return VStack(alignment: .leading, spacing: 10) {
            Text("次に直すと効くもの").font(.caption.bold()).foregroundStyle(.secondary)
            if visible.isEmpty {
                let ackN = s.counts.ack ?? 0
                if ackN > 0 {
                    Label("いま直す項目はありません（\(ackN) 件は確認待ち）", systemImage: "clock.badge.checkmark")
                        .font(.callout).foregroundStyle(.secondary)
                } else {
                    Label("要改善はありません", systemImage: "checkmark.seal.fill")
                        .font(.callout).foregroundStyle(.green)
                }
            } else {
                ForEach(visible) { a in
                    VStack(alignment: .leading, spacing: 4) {
                        HStack(alignment: .top, spacing: 8) {
                            Circle().fill(Color.forScore(s.scoreValue)).frame(width: 6, height: 6).padding(.top, 6)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(a.title).font(.callout).fixedSize(horizontal: false, vertical: true)
                                HStack(spacing: 6) {
                                    Text(a.tierJa).font(.caption2)
                                        .padding(.horizontal, 5).padding(.vertical, 1)
                                        .background(Color.primary.opacity(0.07))
                                        .clipShape(Capsule())
                                    Text(importanceJa(a.weight)).font(.caption2).foregroundStyle(.secondary)
                                }
                            }
                            Spacer()
                            if a.tier == "auto" || a.tier == "confirm" {
                                Button("直す") { confirmFix(a) }
                                    .buttonStyle(.bordered)
                                    .controlSize(.small)
                                    .disabled(busy || fixingId != nil || markingId != nil)
                            } else {
                                Button("対応した") { markDone(a.id) }
                                    .buttonStyle(.bordered)
                                    .controlSize(.small)
                                    .disabled(busy || fixingId != nil || markingId != nil)
                            }
                        }
                        Text(guidance(a)).font(.caption2).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                            .padding(.leading, 14)
                        if fixingId == a.id {
                            HStack(spacing: 6) {
                                ProgressView().controlSize(.small)
                                Text("直しています…").font(.caption2).foregroundStyle(.secondary)
                            }.padding(.leading, 14)
                        } else if markingId == a.id {
                            HStack(spacing: 6) {
                                ProgressView().controlSize(.small)
                                Text("記録しています…").font(.caption2).foregroundStyle(.secondary)
                            }.padding(.leading, 14)
                        }
                    }
                }
            }
        }
    }

    private func importanceJa(_ w: Int) -> String {
        switch w {
        case 6...: return "重要度: 高"
        case 4...5: return "重要度: 中"
        default: return "重要度: 低"
        }
    }

    /// 生の技術文字列ではなく、一般ユーザー向けの案内を返す。
    private func guidance(_ a: TopAction) -> String {
        if !a.how.isEmpty { return a.how }
        switch a.tier {
        case "auto": return "この項目は自動で直せます。実行しても元に戻せます。"
        case "confirm": return "この項目は実行前に確認が必要です。「直す」を押すと内容を確認できます。"
        default: return "この項目は手作業での対応が必要です。"
        }
    }

    private func checksCard(_ s: Status) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            let ackN = s.counts.ack ?? 0
            Text(ackN > 0
                 ? "点検の内訳（できている \(s.counts.ok) / 要改善 \(s.counts.weak) のうち \(ackN) 件は確認待ち）"
                 : "点検の内訳（できている \(s.counts.ok) / 要改善 \(s.counts.weak)）")
                .font(.caption.bold()).foregroundStyle(.secondary)
            ForEach(s.findings.filter { $0.status != "info" }) { f in
                HStack(alignment: .top, spacing: 7) {
                    Image(systemName: f.isOK ? "checkmark.circle.fill"
                          : (f.isAck ? "clock.badge.checkmark"
                             : (f.isUnknown ? "questionmark.circle.fill" : "exclamationmark.triangle.fill")))
                        .foregroundStyle(f.isOK ? .green
                                         : (f.isAck ? .secondary
                                            : (f.isUnknown ? .secondary : .orange)))
                        .font(.caption)
                        .padding(.top, 1)
                    VStack(alignment: .leading, spacing: 1) {
                        Text(f.title).font(.caption)
                        if f.isAck {
                            Text("今日は対応済みとして控えています。直っていなければ明日また表示されます")
                                .font(.caption2).foregroundStyle(.secondary)
                        } else if f.isUnknown {
                            Text("確認できませんでした").font(.caption2).foregroundStyle(.secondary)
                        } else if f.isWeak {
                            let g = (f.how?.isEmpty == false) ? f.how! : "要改善です"
                            Text(g).font(.caption2).foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                    Spacer()
                }
            }
        }
    }

    private func attacksCard(_ s: Status) -> some View {
        Group {
            if let a = s.attacks, a.totalObservations > 0 {
                VStack(alignment: .leading, spacing: 6) {
                    HStack {
                        Label("実際に観測された攻撃", systemImage: "shield.slash")
                            .font(.caption.bold()).foregroundStyle(.secondary)
                        Spacer()
                        Text("\(a.totalObservations)種 / 延べ\(a.totalAttempts)件")
                            .font(.caption2).foregroundStyle(.tertiary)
                    }
                    Text("これは“防げた”記録です。対応は不要です。")
                        .font(.caption2).foregroundStyle(.secondary)
                    ForEach(a.top.prefix(4)) { it in
                        HStack(alignment: .top, spacing: 7) {
                            Image(systemName: "exclamationmark.shield.fill")
                                .foregroundStyle(.orange).font(.caption2).padding(.top, 1)
                            VStack(alignment: .leading, spacing: 1) {
                                Text(it.typeJa).font(.caption2).foregroundStyle(.secondary)
                                Text(it.pattern).font(.caption)
                                    .lineLimit(3).fixedSize(horizontal: false, vertical: true)
                            }
                            Spacer()
                        }
                    }
                }
                .padding(10)
                .background(Color.orange.opacity(0.06))
                .clipShape(RoundedRectangle(cornerRadius: 8))
            }
        }
    }

    private func footer(_ s: Status) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Divider()
            if let f = s.fixedToday, f > 0 {
                Label("今日 \(f) 件を自動で直しました", systemImage: "wrench.and.screwdriver.fill")
                    .font(.caption2).foregroundStyle(.green)
            }
            HStack {
                Text("最終点検 \(s.updated.prefix(16).replacingOccurrences(of: "T", with: " "))")
                    .font(.caption2).foregroundStyle(.tertiary)
                Spacer()
                Link("くわしく見る", destination: URL(string: "https://mamori.teai.io")!)
                    .font(.caption2)
            }
            Text("毎日決まった時刻に自動で点検します").font(.caption2).foregroundStyle(.tertiary)
            Toggle(isOn: Binding(
                get: { LoginItem.isEnabled },
                set: { on in
                    if let err = LoginItem.set(on) {
                        loginError = err
                    } else {
                        loginError = nil
                    }
                }
            )) {
                Text("ログイン時に開く").font(.caption2)
            }
            .toggleStyle(.switch)
            .controlSize(.mini)
            Toggle(isOn: Binding(
                get: { speakEnabled },
                set: { on in
                    speakEnabled = on
                    Speaker.enabled = on
                    if !on { Speaker.stop() }
                }
            )) {
                Text("読み上げる").font(.caption2)
            }
            .toggleStyle(.switch)
            .controlSize(.mini)
            if let le = loginError {
                Text(le).font(.caption2).foregroundStyle(.red)
            }
            if notifyDenied {
                Text("通知がオフです（システム設定 › 通知 › 守 で許可できます）")
                    .font(.caption2).foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let n = notice {
                Text(n).font(.caption2).foregroundStyle(.green)
            }
            if let e = lastError {
                Text(e).font(.caption2).foregroundStyle(.red).fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private func confirmFix(_ a: TopAction) {
        let alert = NSAlert()
        alert.messageText = "「\(a.title)」を直しますか？"
        let base = a.how.isEmpty ? "この項目を自動で修正します。" : a.how
        let undoNote = (a.tier == "confirm")
            ? "\n\n※ 一部の更新は元に戻せません。"
            : ""
        alert.informativeText = base + undoNote
        alert.addButton(withTitle: "直す")
        alert.addButton(withTitle: "やめる")
        alert.alertStyle = .warning
        if alert.runModal() == .alertFirstButtonReturn {
            runFix(a)
        }
    }

    private func runFix(_ a: TopAction) {
        fixingId = a.id; lastError = nil; notice = nil
        Store.fixItem(a.id) { ok, msg, needsAdmin in
            if needsAdmin {
                // 管理者権限が必要 → macOS 標準ダイアログで本人にパスワードを尋ねる
                Store.fixItemAsAdmin(a.id) { ok2, _ in
                    fixingId = nil
                    if ok2 {
                        notice = "直しました。再点検します…"
                        runNow()
                    } else {
                        lastError = "管理者の許可が必要でした。キャンセルした場合は変更されていません。"
                    }
                }
            } else {
                fixingId = nil
                if ok {
                    notice = "直しました\(msg.isEmpty ? "" : "（\(msg)）")。再点検します…"
                    runNow()
                } else {
                    lastError = "直せませんでした（時間をおいて再度お試しください）"
                }
            }
        }
    }

    private func markDone(_ id: String) {
        Store.ack(id)
        acked = Store.loadAck()
        markingId = id
        notice = "今日は表示を控えます。点数は実際に直るまで変わりません（次の点検で確認します）"
        // 表示を今日ぶん静めるため再点検する。点数は実スコアのまま据え置く。
        busy = true
        Store.refresh { ok in
            busy = false
            markingId = nil
            if ok { reload() }
        }
    }

    private func reload() {
        switch Store.loadResult() {
        case .ok(let s): status = s; loadBroken = false
        case .missing: status = nil; loadBroken = false
        case .broken: status = nil; loadBroken = true
        }
        acked = Store.loadAck()
    }

    private func runNow() {
        busy = true; lastError = nil
        let before = status?.scoreValue
        Store.refresh { ok in
            busy = false
            if !ok { lastError = "点検に失敗しました（時間をおいて再度お試しください）" }
            reload()
            if ok, let s = status {
                Speaker.say(Speaker.summary(s))
                if let prev = before, s.scoreValue < prev {
                    Notifier.post(title: "守りの点数が下がりました",
                                  body: "\(prev) → \(s.scoreValue) 点。要改善 \(s.counts.weak) 件。クリックで確認できます。")
                }
            }
        }
    }
}

// MARK: - 通知

enum Notifier {
    static func request() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }
    }
    /// 通知が許可されているか。拒否時は UI に説明を出すために使う。
    static func checkAuthorization(_ completion: @escaping (Bool) -> Void) {
        UNUserNotificationCenter.current().getNotificationSettings { s in
            let ok = s.authorizationStatus == .authorized || s.authorizationStatus == .provisional
            DispatchQueue.main.async { completion(ok) }
        }
    }
    static func post(title: String, body: String) {
        let c = UNMutableNotificationContent()
        c.title = title
        c.body = body
        let req = UNNotificationRequest(identifier: UUID().uuidString, content: c, trigger: nil)
        UNUserNotificationCenter.current().add(req)
    }
}

// MARK: - 読み上げ（声）

/// macOS 標準の音声で守りの状態を読み上げる。外部依存なし。
enum Speaker {
    private static let synth = AVSpeechSynthesizer()

    /// 読み上げが有効か（既定はオン）。フッターのトグルで切り替える。
    static var enabled: Bool {
        get { UserDefaults.standard.object(forKey: "mamori.speak") as? Bool ?? true }
        set { UserDefaults.standard.set(newValue, forKey: "mamori.speak") }
    }

    static func say(_ text: String) {
        guard enabled, !text.isEmpty else { return }
        if synth.isSpeaking { synth.stopSpeaking(at: .immediate) }
        let u = AVSpeechUtterance(string: text)
        u.voice = AVSpeechSynthesisVoice(language: "ja-JP")
        u.rate = AVSpeechUtteranceDefaultSpeechRate * 0.95
        synth.speak(u)
    }

    static func stop() {
        if synth.isSpeaking { synth.stopSpeaking(at: .immediate) }
    }

    /// 点検結果を1文にまとめる（読み上げ用）。
    static func summary(_ s: Status) -> String {
        let weak = s.counts.weak
        let ack = s.counts.ack ?? 0
        var t = "守りの点数は \(s.scoreValue) 点、\(s.grade)です。"
        if weak == 0 {
            t += "要改善の項目はありません。"
        } else if ack > 0 {
            t += "要改善が \(weak) 件あり、うち \(ack) 件は確認待ちです。"
        } else {
            t += "要改善が \(weak) 件あります。"
        }
        if let top = s.topActions.first {
            t += "まずは \(top.title) から。"
        }
        return t
    }
}

// MARK: - ログイン項目

enum LoginItem {
    static var isEnabled: Bool {
        SMAppService.mainApp.status == .enabled
    }
    /// 成功なら nil、失敗なら理由を返す。
    static func set(_ on: Bool) -> String? {
        do {
            if on { try SMAppService.mainApp.register() }
            else { try SMAppService.mainApp.unregister() }
            return nil
        } catch {
            return "設定できませんでした（Applications フォルダに置くと有効になります）"
        }
    }
}

// MARK: - App

final class AppDelegate: NSObject, NSApplicationDelegate, UNUserNotificationCenterDelegate {
    var item: NSStatusItem!
    var popover = NSPopover()
    var menu: NSMenu!
    var timer: Timer?
    var watchTimer: Timer?
    var lastSeenDate: String?

    func applicationDidFinishLaunching(_ n: Notification) {
        NSApp.setActivationPolicy(.accessory)
        UNUserNotificationCenter.current().delegate = self
        Notifier.request()
        Store.syncBundledEngine()
        item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        if let b = item.button {
            b.image = NSImage(systemSymbolName: "shield.lefthalf.filled", accessibilityDescription: "守")
            b.imagePosition = .imageLeading
        }
        updateTitle()
        lastSeenDate = Store.load()?.date

        popover.contentSize = NSSize(width: 400, height: 540)
        popover.behavior = .transient
        popover.contentViewController = NSHostingController(rootView: Panel())
        item.button?.action = #selector(toggle)
        item.button?.target = self
        item.button?.sendAction(on: [.leftMouseUp, .rightMouseUp])

        // 右クリック用メニュー（終了・今すぐ点検）
        let menu = NSMenu()
        let scan = NSMenuItem(title: "今すぐ点検", action: #selector(scanNow), keyEquivalent: "")
        scan.target = self
        menu.addItem(scan)
        menu.addItem(NSMenuItem.separator())
        let quit = NSMenuItem(title: "守を終了", action: #selector(quit), keyEquivalent: "q")
        quit.target = self
        menu.addItem(quit)
        self.menu = menu

        // 30分ごとに表示を更新
        timer = Timer.scheduledTimer(withTimeInterval: 1800, repeats: true) { [weak self] _ in
            self?.updateTitle()
        }
        // 60秒ごとに status.json の変化を監視（launchd の毎日点検の結果を拾う）
        watchTimer = Timer.scheduledTimer(withTimeInterval: 60, repeats: true) { [weak self] _ in
            self?.checkForUpdate()
        }

        // 初回（記録なし）は起動直後に自動で点検を始める。ポップオーバーを開かなくても走る。
        if !Store.hasStatus() {
            DispatchQueue.global(qos: .utility).async {
                if Store.dailyPath != nil, Store.pythonPath() != nil {
                    DispatchQueue.main.async {
                        Store.refresh { [weak self] _ in self?.updateTitle() }
                    }
                }
            }
        }
    }

    @objc func toggle() {
        guard let b = item.button else { return }
        if NSApp.currentEvent?.type == .rightMouseUp {
            menu.popUp(positioning: nil, at: NSPoint(x: 0, y: b.bounds.height + 4), in: b)
            return
        }
        if popover.isShown { popover.performClose(nil) }
        else {
            updateTitle()
            popover.show(relativeTo: b.bounds, of: b, preferredEdge: .minY)
            popover.contentViewController?.view.window?.makeKey()
        }
    }

    @objc func scanNow() {
        Store.refresh { [weak self] _ in self?.updateTitle(); self?.checkForUpdate(force: true) }
    }

    @objc func quit() {
        NSApp.terminate(nil)
    }

    /// status.json が外部（launchd）で更新されたら通知する。
    /// 手動点検のたびに二重通知しないよう、日付が変わった時だけ知らせる。
    func checkForUpdate(force: Bool = false) {
        updateTitle()
        guard let s = Store.load() else { return }
        if let prev = lastSeenDate, prev != s.date {
            Notifier.post(title: "守の点検が更新されました",
                          body: "守りの点数 \(s.scoreValue)（\(s.grade)）。要改善 \(s.counts.weak) 件。")
        } else if force {
            Notifier.post(title: "守の点検が完了しました",
                          body: "守りの点数 \(s.scoreValue)（\(s.grade)）。")
        }
        lastSeenDate = s.date
    }

    func updateTitle() {
        guard let s = Store.load() else {
            item.button?.title = " –"
            return
        }
        item.button?.title = " \(s.scoreValue)"
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter,
                                willPresent notification: UNNotification,
                                withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        completionHandler([.banner, .sound])
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter,
                                didReceive response: UNNotificationResponse,
                                withCompletionHandler completionHandler: @escaping () -> Void) {
        DispatchQueue.main.async { [weak self] in
            guard let self, let b = self.item.button else { completionHandler(); return }
            if !self.popover.isShown {
                self.updateTitle()
                self.popover.show(relativeTo: b.bounds, of: b, preferredEdge: .minY)
                self.popover.contentViewController?.view.window?.makeKey()
            }
        }
        completionHandler()
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.run()
