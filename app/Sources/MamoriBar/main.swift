import AppKit
import SwiftUI

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

    enum CodingKeys: String, CodingKey {
        case id, title, status, detail, weight, tier
        case statusJa = "status_ja"
        case tierJa = "tier_ja"
    }

    var isOK: Bool { status == "ok" }
    var isWeak: Bool { status == "weak" }
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

    /// python3 を探す（/usr/bin, /opt/homebrew, /usr/local）。
    static var pythonPath: String? {
        let candidates = ["/usr/bin/python3", "/opt/homebrew/bin/python3", "/usr/local/bin/python3"]
        return candidates.first { FileManager.default.isExecutableFile(atPath: $0) }
    }

    static func load() -> Status? {
        guard let data = try? Data(contentsOf: statusPath) else { return nil }
        return try? JSONDecoder().decode(Status.self, from: data)
    }

    static func hasStatus() -> Bool {
        FileManager.default.fileExists(atPath: statusPath.path)
    }

    /// 点検を今すぐ実行する（daily.py --fix）。重いのでバックグラウンドで。
    static func refresh(completion: @escaping (Bool) -> Void) {
        guard let daily = dailyPath, let py = pythonPath else {
            completion(false); return
        }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: py)
        p.arguments = [daily.path, "--fix", "--quiet"]
        p.standardOutput = Pipe()
        p.standardError = Pipe()
        p.terminationHandler = { proc in
            DispatchQueue.main.async { completion(proc.terminationStatus == 0) }
        }
        do { try p.run() } catch { completion(false) }
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
    }
}

// MARK: - ポップオーバー

struct Panel: View {
    @State private var status: Status?
    @State private var busy = false
    @State private var lastError: String?

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
                .frame(maxHeight: 460)
            } else {
                VStack(spacing: 12) {
                    if busy {
                        ProgressView()
                        Text("この Mac の守りを点検しています…").font(.callout).foregroundStyle(.secondary)
                        Text("初回は1〜2分かかることがあります。").font(.caption).foregroundStyle(.tertiary)
                    } else if Store.dailyPath == nil || Store.pythonPath == nil {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .font(.largeTitle).foregroundStyle(.orange)
                        Text("点検エンジンが見つかりません").font(.callout).foregroundStyle(.secondary)
                        Text("アプリを Applications フォルダに置いた状態で開き直してください。")
                            .font(.caption).foregroundStyle(.tertiary)
                            .multilineTextAlignment(.center)
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
        .frame(width: 380)
        .onAppear {
            reload()
            // 初回（記録なし）は自動で点検を始める。エンジンが無ければ何もしない。
            if status == nil, !busy, Store.dailyPath != nil, Store.pythonPath != nil {
                runNow()
            }
        }
    }

    private var header: some View {
        HStack(alignment: .center, spacing: 12) {
            ZStack {
                Circle().fill(Color.forScore(status?.scoreValue ?? 0).opacity(0.15)).frame(width: 56, height: 56)
                Text(status.map { "\($0.scoreValue)" } ?? "–")
                    .font(.system(size: 24, weight: .bold, design: .rounded))
                    .foregroundStyle(Color.forScore(status?.scoreValue ?? 0))
            }
            VStack(alignment: .leading, spacing: 2) {
                Text("守りの点数").font(.headline)
                if let s = status {
                    HStack(spacing: 6) {
                        Text(s.grade).font(.subheadline).foregroundStyle(.secondary)
                        if let d = s.delta, d != 0 {
                            Text(d > 0 ? "+\(d)" : "\(d)")
                                .font(.caption.bold())
                                .padding(.horizontal, 6).padding(.vertical, 1)
                                .background((d > 0 ? Color.green : Color.red).opacity(0.15))
                                .foregroundStyle(d > 0 ? .green : .red)
                                .clipShape(Capsule())
                        }
                    }
                } else {
                    Text("未記録").font(.subheadline).foregroundStyle(.secondary)
                }
            }
            Spacer()
            Button {
                runNow()
            } label: {
                if busy { ProgressView().controlSize(.small) }
                else { Image(systemName: "arrow.clockwise") }
            }
            .buttonStyle(.borderless)
            .help("今すぐ点検して、直せるものは自動で直す")
            .disabled(busy)
        }
        .padding(14)
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
        VStack(alignment: .leading, spacing: 8) {
            Text("次に直すと効くもの").font(.caption.bold()).foregroundStyle(.secondary)
            if s.topActions.isEmpty {
                Label("要改善はありません", systemImage: "checkmark.seal.fill")
                    .font(.callout).foregroundStyle(.green)
            } else {
                ForEach(s.topActions) { a in
                    HStack(alignment: .top, spacing: 8) {
                        Circle().fill(Color.forScore(s.scoreValue)).frame(width: 6, height: 6).padding(.top, 6)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(a.title).font(.callout).fixedSize(horizontal: false, vertical: true)
                            HStack(spacing: 6) {
                                Text(a.tierJa).font(.caption2)
                                    .padding(.horizontal, 5).padding(.vertical, 1)
                                    .background(Color.primary.opacity(0.07))
                                    .clipShape(Capsule())
                                Text("重み \(a.weight)").font(.caption2).foregroundStyle(.secondary)
                            }
                        }
                        Spacer()
                    }
                }
            }
        }
    }

    private func checksCard(_ s: Status) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("点検の内訳（できている \(s.counts.ok) / 要改善 \(s.counts.weak)）")
                .font(.caption.bold()).foregroundStyle(.secondary)
            ForEach(s.findings.filter { $0.status != "info" }) { f in
                HStack(alignment: .top, spacing: 7) {
                    Image(systemName: f.isOK ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                        .foregroundStyle(f.isOK ? .green : .orange)
                        .font(.caption)
                        .padding(.top, 1)
                    VStack(alignment: .leading, spacing: 1) {
                        Text(f.title).font(.caption)
                        if f.isWeak && !f.detail.isEmpty {
                            Text(f.detail).font(.caption2).foregroundStyle(.secondary)
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
                    ForEach(a.top.prefix(4)) { it in
                        HStack(alignment: .top, spacing: 7) {
                            Image(systemName: "exclamationmark.shield.fill")
                                .foregroundStyle(.orange).font(.caption2).padding(.top, 1)
                            VStack(alignment: .leading, spacing: 1) {
                                Text(it.typeJa).font(.caption2).foregroundStyle(.secondary)
                                Text(it.pattern).font(.caption)
                                    .lineLimit(2).fixedSize(horizontal: false, vertical: true)
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
        VStack(alignment: .leading, spacing: 6) {
            Divider()
            HStack {
                Text("更新 \(s.updated.prefix(16).replacingOccurrences(of: "T", with: " "))")
                    .font(.caption2).foregroundStyle(.tertiary)
                Spacer()
                Link("くわしく見る", destination: URL(string: "https://mamori.teai.io")!)
                    .font(.caption2)
            }
            if let e = lastError {
                Text(e).font(.caption2).foregroundStyle(.red)
            }
        }
    }

    private func reload() {
        status = Store.load()
    }

    private func runNow() {
        busy = true; lastError = nil
        Store.refresh { ok in
            busy = false
            if !ok { lastError = "点検に失敗しました（時間をおいて再度お試しください）" }
            reload()
        }
    }
}

// MARK: - App

final class AppDelegate: NSObject, NSApplicationDelegate {
    var item: NSStatusItem!
    var popover = NSPopover()
    var timer: Timer?

    func applicationDidFinishLaunching(_ n: Notification) {
        NSApp.setActivationPolicy(.accessory)
        item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        if let b = item.button {
            b.image = NSImage(systemSymbolName: "shield.lefthalf.filled", accessibilityDescription: "守")
            b.imagePosition = .imageLeading
        }
        updateTitle()

        popover.contentSize = NSSize(width: 380, height: 520)
        popover.behavior = .transient
        popover.contentViewController = NSHostingController(rootView: Panel())
        item.button?.action = #selector(toggle)
        item.button?.target = self

        // 30分ごとに表示を更新
        timer = Timer.scheduledTimer(withTimeInterval: 1800, repeats: true) { [weak self] _ in
            self?.updateTitle()
        }

        // 初回（記録なし）は起動直後に自動で点検を始める。ポップオーバーを開かなくても走る。
        if !Store.hasStatus(), Store.dailyPath != nil, Store.pythonPath != nil {
            Store.refresh { [weak self] _ in self?.updateTitle() }
        }
    }

    @objc func toggle() {
        guard let b = item.button else { return }
        if popover.isShown { popover.performClose(nil) }
        else {
            updateTitle()
            popover.show(relativeTo: b.bounds, of: b, preferredEdge: .minY)
            popover.contentViewController?.view.window?.makeKey()
        }
    }

    func updateTitle() {
        guard let s = Store.load() else {
            item.button?.title = " –"
            return
        }
        item.button?.title = " \(s.scoreValue)"
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.run()
