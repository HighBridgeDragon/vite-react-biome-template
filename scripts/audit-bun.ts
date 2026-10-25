import { readFileSync } from "node:fs";
import { resolve } from "node:path";

export interface Vulnerability {
	package?: { name?: string };
	vulnerable_version_range?: string;
	patched_versions?: string;
}

export interface Advisory {
	ghsa_id: string;
	summary: string;
	severity: "critical" | "high" | "moderate" | "low" | string;
	vulnerabilities?: Vulnerability[];
}

/**
 * セマンティックバージョン文字列をパースして [major, minor, patch] の数値タプルを返します。
 * プレリリース記号（-canary など）や v プレフィックスにも対応します。
 */
export function parseSemver(v: string): [number, number, number] {
	const cleaned = v.trim().replace(/^v/, "");
	const mainPart = cleaned.split("-")[0];
	const parts = mainPart.split(".").map((n) => Number.parseInt(n, 10));
	return [parts[0] || 0, parts[1] || 0, parts[2] || 0];
}

/**
 * 2 つのセマンティックバージョンを比較します。
 * v1 > v2 => 正の数, v1 < v2 => 負の数, v1 == v2 => 0
 */
export function compareSemver(v1: string, v2: string): number {
	const [maj1, min1, pat1] = parseSemver(v1);
	const [maj2, min2, pat2] = parseSemver(v2);

	if (maj1 !== maj2) return maj1 - maj2;
	if (min1 !== min2) return min1 - min2;
	if (pat1 !== pat2) return pat1 - pat2;

	// 同一の主要番号で片方にプレリリースがある場合、プレリリース付きは通常版より小さい
	const hasPre1 = v1.includes("-");
	const hasPre2 = v2.includes("-");
	if (hasPre1 && !hasPre2) return -1;
	if (!hasPre1 && hasPre2) return 1;

	return 0;
}

/**
 * 単一またはカンマ区切りのバージョン範囲条件を評価する関数を返します。
 * 例: ">= 1.3.14, < 1.4.4", "< 1.4.4"
 */
export function parseVersionRange(range: string): (v: string) => boolean {
	const clauses = range
		.split(",")
		.map((c) => c.trim())
		.filter(Boolean);

	const parsedClauses = clauses.map((clause) => {
		const match = clause.match(/^([><=!]+)\s*(.+)$/);
		if (!match) {
			return () => false;
		}
		const op = match[1];
		const target = match[2].trim();

		return (ver: string) => {
			const cmp = compareSemver(ver, target);
			switch (op) {
				case ">":
					return cmp > 0;
				case ">=":
					return cmp >= 0;
				case "<":
					return cmp < 0;
				case "<=":
					return cmp <= 0;
				case "=":
				case "==":
					return cmp === 0;
				default:
					return false;
			}
		};
	});

	return (v: string) => parsedClauses.every((check) => check(v));
}

/**
 * mise.toml の文字列から bun バージョンを抽出します。
 */
export function extractBunVersionFromToml(content: string): string | null {
	const match = content.match(/bun\s*=\s*["']([^"']+)["']/);
	return match ? match[1] : null;
}

/**
 * Advisory 一覧とバージョンを照合し、該当する Advisory を抽出します。
 */
export function checkAdvisories(
	currentVersion: string,
	advisories: Advisory[],
): { hasCriticalOrHigh: boolean; matched: Advisory[] } {
	const matched: Advisory[] = [];
	let hasCriticalOrHigh = false;

	for (const advisory of advisories) {
		const vulns = advisory.vulnerabilities || [];
		const isTargetVulnerable = vulns.some((vuln) => {
			if (!vuln.vulnerable_version_range) return false;
			const isVulnerable = parseVersionRange(vuln.vulnerable_version_range);
			return isVulnerable(currentVersion);
		});

		if (isTargetVulnerable) {
			matched.push(advisory);
			const severity = (advisory.severity || "").toLowerCase();
			if (severity === "critical" || severity === "high") {
				hasCriticalOrHigh = true;
			}
		}
	}

	return { hasCriticalOrHigh, matched };
}

export interface AuditBunOptions {
	version?: string;
	tomlPath?: string;
	fetchFn?: typeof fetch;
}

/**
 * Bun のバージョンを上流 GitHub Security Advisories と照合します。
 * 終了コード: 0（安全またはオフライン通過）, 1（High/Critical 検出）
 */
export async function auditBun(options: AuditBunOptions = {}): Promise<number> {
	const fetchFn = options.fetchFn || globalThis.fetch;
	let version = options.version;

	if (!version) {
		const tomlPath = options.tomlPath || resolve(process.cwd(), "mise.toml");
		try {
			const tomlContent = readFileSync(tomlPath, "utf-8");
			version = extractBunVersionFromToml(tomlContent) || undefined;
		} catch (e) {
			console.warn(`[WARN] ${tomlPath} を読み込めませんでした:`, e);
		}
	}

	if (!version) {
		console.warn(
			"[WARN] 検証対象の Bun バージョンを特定できませんでした。検査をスキップします。",
		);
		return 0;
	}

	console.log(`[audit:bun] 検証対象の Bun バージョン: ${version}`);

	const apiUrl =
		"https://api.github.com/repos/oven-sh/bun/security-advisories?state=published&per_page=100";
	const headers: Record<string, string> = {
		"User-Agent": "bun-audit-hook",
	};

	const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
	if (token) {
		headers.Authorization = `Bearer ${token}`;
	}

	let advisories: Advisory[] = [];
	try {
		const res = await fetchFn(apiUrl, { headers });
		if (!res.ok) {
			console.warn(
				`[WARN] GitHub Security Advisories API への接続に失敗しました (ステータス: ${res.status})。オフライン等のため検査をスキップします。`,
			);
			return 0;
		}
		advisories = (await res.json()) as Advisory[];
	} catch (err) {
		console.warn(
			"[WARN] ネットワーク不通のため GitHub Security Advisories の取得をスキップします:",
			(err as Error).message,
		);
		return 0;
	}

	const { hasCriticalOrHigh, matched } = checkAdvisories(version, advisories);

	if (matched.length === 0) {
		console.log(
			`[audit:bun] Bun ${version} に該当する公開された脆弱性はありません。`,
		);
		return 0;
	}

	console.log(
		`\n[audit:bun] 注意: Bun ${version} に影響する脆弱性が ${matched.length} 件検出されました:`,
	);
	for (const a of matched) {
		console.log(`  - [${a.severity.toUpperCase()}] ${a.ghsa_id}: ${a.summary}`);
		for (const v of a.vulnerabilities || []) {
			console.log(
				`      影響範囲: ${v.vulnerable_version_range} (修正版: ${v.patched_versions || "未定"})`,
			);
		}
	}

	if (hasCriticalOrHigh) {
		console.error(
			"\n[ERROR] High または Critical の脆弱性が検出されたため、処理を中断します。",
		);
		return 1;
	}

	console.warn(
		"\n[WARN] Moderate または Low の脆弱性のみのため、処理を続行します。",
	);
	return 0;
}

// CLI 直実行時
if (import.meta.main) {
	const args = process.argv.slice(2);
	let cliVersion: string | undefined;
	const verIdx = args.indexOf("--version");
	if (verIdx !== -1 && args[verIdx + 1]) {
		cliVersion = args[verIdx + 1];
	}

	const exitCode = await auditBun({ version: cliVersion });
	process.exit(exitCode);
}
