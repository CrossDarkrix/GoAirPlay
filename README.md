# GoAirPlay

iPhone / Mac から AirPlay で音楽を受けて、PC やスマホで再生する受信サーバーです。Go のみで実装しています。

An AirPlay audio receiver written in pure Go. Stream music from an iPhone or Mac to your Windows PC speakers / USB DAC, or to an Android phone.

## 動作環境 / Platforms

| 対象 | 状態 |
|---|---|
| Windows (GoAirPlay.exe) | スピーカー / USB DAC からライブ再生 |
| Android | 専用アプリ版があります（下記） |
| Termux (CLI) | 発見・受信・復号まで動作。音声出力は ffplay / mpv / paplay があれば再生 |

## 使い方（Windows）/ Usage

1. `GoAirPlay.exe` を実行する（初回は Windows ファイアウォールの許可ダイアログで「許可」）
2. iPhone のコントロールセンター → AirPlay アイコン → **GoAirPlay** を選択
3. PC から音楽が流れます。音量は iPhone 側のボリュームに追従します

Run `GoAirPlay.exe`, allow it through the Windows Firewall, then pick **GoAirPlay** from the iPhone AirPlay list.

## オプション / Options

| フラグ | 既定値 | 説明 |
|---|---|---|
| `-name` | `GoAirPlay` | AirPlay 一覧に表示される名前 |
| `-port` | `7000` | RTSP ポート |
| `-record` | off | デコードした音声を `goairplay_out.wav` にも記録（デバッグ用） |
| `-browse` | off | 診断用：LAN 内の AirPlay 受信機を mDNS で一覧表示して終了 |

## Android アプリ版 / Android app

スマホ本体から音を出す場合は、姉妹プロジェクトの Android アプリ版がおすすめです。Go 受信機を内蔵し、マルチキャストロックと AudioTrack 出力をアプリ側で担います。

- GoAirPlay for Android: https://github.com/CrossDarkrix/GoAirPlay-for-Android

For playback on an Android phone itself, use the companion Android app, which embeds this receiver and handles the multicast lock and audio output natively.

## ビルド / Build

```
# Windows
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o GoAirPlay.exe .
# Termux / Android (CLI binary)
CGO_ENABLED=0 GOOS=android GOARCH=arm64 go build -o GoAirPlay-termux .
```

## 技術メモ / Notes

- 発見: mDNS (`_raop._tcp` + `_airplay._tcp`、ポート 7000)。通常は zeroconf ライブラリ、インターフェース列挙が使えない環境（Android/Termux）では内蔵の最小 mDNS 実装に自動で切り替わります
- 認証: pair-verify (Ed25519/X25519)、FairPlay v3 ハンドシェイク
- 音声鍵: `SHA-512(playfair復号鍵 ‖ ECDH共有秘密)` の先頭16バイト
- 復号: AES-CBC (RAOP) → ALAC デコード → Windows は winmm (waveOut)、Linux/Android は外部プレイヤーまたは stdout (PCM) へ出力

## ライセンス / License

MIT License. Copyright (c) CrossDarkrix.

FairPlay ハンドシェイクの応答データ等、プロトコル上固定の値については公開されている実装資料を参照し、コードは独自に実装しています。
