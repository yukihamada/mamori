#!/usr/bin/env python3
"""Mamori「初めての共有」説明動画 (tasks/video-request.md)

台本 → teai /api/v1/voice/* (voice=yukihamada) で本人声合成 →
PILでスライド(字幕焼き込み) → ffmpeg で 1920x1080 MP4。
出力: ~/workspace/mamori/media/mamori-first-share.mp4 / .jpg
"""
import json, os, subprocess, sys, time, uuid, urllib.request

BASE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.join(BASE, "work-first-share")
OUT = os.path.expanduser("~/workspace/mamori/media/mamori-first-share.mp4")
JPG = OUT.replace(".mp4", ".jpg")
FONT = "/System/Library/Fonts/ヒラギノ角ゴシック W6.ttc"
FONT3 = "/System/Library/Fonts/ヒラギノ角ゴシック W3.ttc"
CREAM, GOLD, DIM, BG = (246, 239, 230), (229, 176, 106), (170, 160, 148), (12, 10, 8)
W, H = 1920, 1080

# (display_title, subtitle(字幕=読みそのまま), tts_text)
SEGMENTS = [
    ("攻撃、来てないと\n思ってませんか？",
     "自分のサーバー、攻撃なんて来てないと思っていませんか。私もそう思っていました。",
     "自分のサーバー、攻撃なんて来てないと思っていませんか。私もそう思っていました。"),
    ("でも、もう来ていました",
     "ログを調べたら、phpinfoを探す探索、Reactの脆弱性を突く試行、難読化されたバックドアの探索。一日で三件、見つかりました。",
     "ログを調べたら、ぴーえいちぴーインフォを探す探索、Reactの脆弱性を突く試行、難読化されたバックドアの探索。一日で三件、見つかりました。"),
    ("「来てない」じゃなく\n「見えてない」だけ",
     "大企業だけが狙われるんじゃありません。守りの薄い中小こそ狙われます。攻撃は来ていないのではなく、見えていないだけなんです。",
     "大企業だけが狙われるんじゃありません。守りの薄い中小こそ狙われます。攻撃は来ていないのではなく、見えていないだけなんです。"),
    ("1社の観測が、\nみんなの防御になる",
     "そこでMamoriです。見つけた攻撃を匿名で共有すれば、一社の観測がみんなの防御になります。",
     "そこでMamoriです。見つけた攻撃を匿名で共有すれば、一社の観測がみんなの防御になります。"),
    ("正直な約束",
     "ひとつ正直に言います。安全になったことを統計的に証明することはできません。だからMamoriは、効果を過剰に約束しません。",
     "ひとつ正直に言います。安全になったことを統計的に証明することはできません。だからMamoriは、効果を過剰に約束しません。"),
    ("最新の脅威を6時間ごとに。\n無料で。",
     "代わりに、最新の脅威情報を六時間ごとにお届けし、あなたの環境と照合できるキットを無料で提供します。Mamori、まもりを、始めましょう。",
     "代わりに、最新の脅威情報を六時間ごとにお届けし、あなたの環境と照合できるキットを無料で提供します。Mamori、まもりを、始めましょう。"),
]


def api_key():
    k = os.environ.get("TEAI_API_KEY")
    if not k:
        raise RuntimeError("TEAI_API_KEY が無い")
    return k


def speak(text, out, voice="yukihamada"):
    """teai 正規課金経路で本人声を合成し out に保存。"""
    key = api_key()
    api = "https://api.teai.io"
    hdr = {"Authorization": "Bearer " + key, "Content-Type": "application/json"}
    q = json.load(urllib.request.urlopen(urllib.request.Request(
        api + "/api/v1/voice/quote", data=json.dumps({"voice": voice}).encode(),
        headers=hdr), timeout=60))
    credits = int(q.get("credits", 0))
    if credits > 15:
        raise RuntimeError(f"料金が上限超: {q}")
    rid = str(uuid.uuid4())
    print(f"  quote {credits}cr / request_id={rid}", flush=True)
    g = json.load(urllib.request.urlopen(urllib.request.Request(
        api + "/api/v1/voice/generate", data=json.dumps({
            "voice": voice, "text": text[:600], "request_id": rid,
            "confirmed_credits": credits, "speed": 1.0, "lang": "ja"}).encode(),
        headers=hdr), timeout=120))
    for _ in range(90):
        if g.get("state") == "complete":
            break
        time.sleep(2)
        g = json.load(urllib.request.urlopen(urllib.request.Request(
            api + "/api/v1/voice/purchases/" + rid,
            headers={"Authorization": "Bearer " + key}), timeout=60))
    if g.get("state") != "complete":
        raise RuntimeError(f"complete にならない: {g.get('state')}")
    data = urllib.request.urlopen(urllib.request.Request(
        api + "/api/v1/voice/purchases/" + rid + "/audio",
        headers={"Authorization": "Bearer " + key}), timeout=120).read()
    if len(data) <= 1000:
        raise RuntimeError(f"音声が小さい {len(data)}B")
    open(out, "wb").write(data)
    return out


def wrap(text, font, max_w, draw):
    lines, cur = [], ""
    for ch in text:
        if ch == "\n":
            lines.append(cur); cur = ""; continue
        if draw.textlength(cur + ch, font=font) > max_w and cur:
            lines.append(cur); cur = ch
        else:
            cur += ch
    if cur:
        lines.append(cur)
    return lines


def slide(title, subtitle, out):
    from PIL import Image, ImageDraw, ImageFont
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    ft = ImageFont.truetype(FONT, 92)
    fs = ImageFont.truetype(FONT3, 40)
    fb = ImageFont.truetype(FONT, 44)
    # タイトル中央
    tl = title.split("\n")
    th = len(tl) * 120
    y = (H - th) // 2 - 60
    for ln in tl:
        w = d.textlength(ln, font=ft)
        d.text(((W - w) / 2, y), ln, font=ft, fill=CREAM)
        y += 120
    # ゴールドのライン
    d.rectangle([W / 2 - 60, y + 10, W / 2 + 60, y + 16], fill=GOLD)
    # 字幕(下部帯)
    d.rectangle([0, H - 190, W, H], fill=(0, 0, 0))
    sl = wrap(subtitle, fs, W - 240, d)
    sy = H - 190 + (190 - len(sl) * 56) / 2
    for ln in sl:
        w = d.textlength(ln, font=fs)
        d.text(((W - w) / 2, sy), ln, font=fs, fill=(235, 228, 218))
        sy += 56
    # ブランド
    d.text((60, 44), "Mamori", font=fb, fill=GOLD)
    bw = d.textlength("mamori.teai.io", font=ImageFont.truetype(FONT3, 32))
    d.text((W - bw - 60, 52), "mamori.teai.io", font=ImageFont.truetype(FONT3, 32), fill=DIM)
    img.save(out)
    return out


def dur(path):
    return float(subprocess.run(["ffprobe", "-v", "error", "-show_entries", "format=duration",
                                 "-of", "default=nw=1:nk=1", path],
                                capture_output=True, text=True).stdout.strip())


def main():
    os.makedirs(WORK, exist_ok=True)
    parts = []
    for i, (title, sub, tts) in enumerate(SEGMENTS):
        mp3 = os.path.join(WORK, f"seg{i}.mp3")
        png = os.path.join(WORK, f"seg{i}.png")
        seg = os.path.join(WORK, f"seg{i}.mp4")
        if not os.path.exists(mp3):
            print(f"[{i}] 合成: {tts[:30]}...", flush=True)
            speak(tts, mp3)
        if not os.path.exists(png):
            slide(title, sub, png)
        d = dur(mp3) + 0.6
        subprocess.run(["ffmpeg", "-y", "-loop", "1", "-i", png, "-i", mp3,
                        "-c:v", "libx264", "-t", f"{d:.2f}", "-pix_fmt", "yuv420p",
                        "-c:a", "aac", "-b:a", "160k", "-r", "30", seg],
                       check=True, capture_output=True)
        parts.append(seg)
        print(f"[{i}] {d:.1f}s", flush=True)
    lst = os.path.join(WORK, "list.txt")
    open(lst, "w").write("".join(f"file '{p}'\n" for p in parts))
    subprocess.run(["ffmpeg", "-y", "-f", "concat", "-safe", "0", "-i", lst,
                    "-c", "copy", OUT], check=True, capture_output=True)
    subprocess.run(["ffmpeg", "-y", "-i", OUT, "-ss", "1", "-frames:v", "1",
                    "-q:v", "3", JPG], check=True, capture_output=True)
    print(f"完成: {OUT} ({dur(OUT):.1f}s) / {JPG}", flush=True)


if __name__ == "__main__":
    main()
