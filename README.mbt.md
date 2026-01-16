# dns-checker

MoonBit製のDNSレコードチェッカー。メール送信ドメインの設定状況を確認できます。

## チェック項目

- **TXT** - ドメイン検証、SPF
- **DMARC** - メール認証ポリシー
- **DKIM** - 電子署名 (CNAME)

## インストール

### 前提条件

- [MoonBit](https://www.moonbitlang.com/) (v0.1.x以上)
- macOS または Linux
- `dig` コマンド

### ビルド & インストール

```bash
git clone git@github.com:O6lvl4/dns-checker.git
cd dns-checker
make install
```

`~/.local/bin` にインストールされます。PATHに追加してください:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

## 使い方

```bash
# ヘルプ
dns-checker --help

# ドメインをチェック
dns-checker example.com
```

### 出力例

```
=== DNS Record Checker ===
Domain: example.com

[OK] TXT @ example.com
    Found: "v=spf1 ..."

[OK] TXT @ example.com (SPF)
    SPF record found

[OK] DMARC @ _dmarc.example.com
    DMARC record found

[NG] DKIM @ selector1._domainkey.example.com
    No DKIM CNAME record found

=== Summary: 3/4 passed ===
```

## Makefile コマンド

| コマンド | 説明 |
|---------|------|
| `make build` | ビルド |
| `make run DOMAIN=xxx` | 実行 |
| `make install` | `~/.local/bin` にインストール |
| `make uninstall` | アンインストール |
| `make clean` | ビルド成果物を削除 |

## 技術スタック

- **言語**: [MoonBit](https://www.moonbitlang.com/)
- **非同期ランタイム**: moonbitlang/async
- **ターゲット**: Native (macOS/Linux)

## ライセンス

Apache-2.0
