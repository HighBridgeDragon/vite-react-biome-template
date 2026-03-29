# vite-react-biome-template

Vite + React 19 + TypeScript のプロジェクトテンプレート

## 技術スタック

- React 19 (React Compiler 有効)
- Vite 8
- TypeScript 5.9
- Biome (Linter / Formatter)
- Husky (pre-commit hook)
- Claude Code GitHub Actions (コードレビュー / Issue対応)

## 使い方

1. "Use this template" ボタンからリポジトリを作成
2. `bun install`
3. `bun run dev`

## スクリプト一覧

- `bun run dev` — 開発サーバー起動
- `bun run build` — ビルド
- `bun run lint` — Biome でリント
- `bun run format` — Biome でフォーマット
- `bun run check:fix` — Biome でリント＋自動修正
- `bun run preview` — ビルド結果のプレビュー

## 規約

AGENTS.md を参照
