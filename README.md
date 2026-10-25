# vite-react-biome-template

Vite + React 19 + TypeScript のプロジェクトテンプレート

## 技術スタック

- React 19 (React Compiler 有効)
- Vite 8
- TypeScript 5.9
- Biome (Linter / Formatter)
- Husky (pre-commit / pre-push hook)
- mise (ランタイムバージョン管理)
- Claude Code GitHub Actions (コードレビュー / Issue対応)

## 開発環境のセットアップ

本テンプレートは `mise` で Bun のバージョンを固定しています。

```bash
# mise が導入されている場合、指定バージョンをインストール
mise install

# 依存パッケージの導入
bun install
```

## 使い方

1. "Use this template" ボタンからリポジトリを作成
2. `mise install && bun install`
3. `bun run dev`

## スクリプト一覧

- `bun run dev` — 開発サーバー起動
- `bun run build` — ビルド
- `bun run lint` — Biome でリント
- `bun run format` — Biome でフォーマット
- `bun run check:fix` — Biome でリント＋自動修正
- `bun run preview` — ビルド結果のプレビュー
- `bun run test` — 単体テスト実行
- `bun run audit:deps` — 依存パッケージの脆弱性検査（Critical）
- `bun run audit:tools` — 上流 Bun ランタイムの脆弱性照合
- `bun run audit:all` — 依存パッケージおよび Bun ランタイムの全件検査

## セキュリティ検査（Git フック）

Husky によるローカルフックを設定しています。

- **pre-commit**: ステージされたファイルに Biome による検査・整形を実行します。
- **pre-push**:
  - `bun.lock` の変更時: `bun audit --audit-level=critical` を実行し、Critical 脆弱性があれば push を中断します。
  - `mise.toml` の変更時: 上流リポジトリ（`oven-sh/bun`）の公開 Advisory と照合し、High 以上の脆弱性があれば push を中断します。
  - オフライン時や外部 API 障害時は、警告を表示した上で push を許可します。

### フックのスキップ

緊急時やオフライン時にフックの検査を回避して push する必要がある場合は、`--no-verify` オプションを使用します。

```bash
git push --no-verify
```

## 規約

AGENTS.md を参照
