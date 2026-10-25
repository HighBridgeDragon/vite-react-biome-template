import { describe, expect, it } from "bun:test";
import {
	type Advisory,
	auditBun,
	checkAdvisories,
	compareSemver,
	extractBunVersionFromToml,
	parseVersionRange,
} from "./audit-bun";

describe("compareSemver", () => {
	it("同じバージョンを 0 と判定する", () => {
		expect(compareSemver("1.4.4", "1.4.4")).toBe(0);
	});

	it("パッチバージョンの大小を正しく判定する", () => {
		expect(compareSemver("1.4.4", "1.4.3")).toBeGreaterThan(0);
		expect(compareSemver("1.4.3", "1.4.4")).toBeLessThan(0);
	});

	it("マイナーバージョンの大小を正しく判定する", () => {
		expect(compareSemver("1.5.0", "1.4.9")).toBeGreaterThan(0);
		expect(compareSemver("1.3.14", "1.4.0")).toBeLessThan(0);
	});

	it("メジャーバージョンの大小を正しく判定する", () => {
		expect(compareSemver("2.0.0", "1.9.9")).toBeGreaterThan(0);
		expect(compareSemver("0.9.0", "1.0.0")).toBeLessThan(0);
	});

	it("v プレフィックスを許容する", () => {
		expect(compareSemver("v1.4.4", "1.4.4")).toBe(0);
	});

	it("プレリリースサフィックスが付いた場合も基本パッチ番号で比較できる", () => {
		expect(compareSemver("1.4.4-canary.1", "1.4.3")).toBeGreaterThan(0);
		expect(compareSemver("1.4.4-canary.1", "1.4.4")).toBeLessThanOrEqual(0);
	});
});

describe("parseVersionRange", () => {
	it("単一条件（< 1.4.4）を評価できる", () => {
		const isVulnerable = parseVersionRange("< 1.4.4");
		expect(isVulnerable("1.4.3")).toBe(true);
		expect(isVulnerable("1.4.4")).toBe(false);
		expect(isVulnerable("1.4.5")).toBe(false);
	});

	it("単一条件（<= 1.4.3）を評価できる", () => {
		const isVulnerable = parseVersionRange("<= 1.4.3");
		expect(isVulnerable("1.4.3")).toBe(true);
		expect(isVulnerable("1.4.4")).toBe(false);
	});

	it("複合条件（>= 1.3.14, < 1.4.4）を評価できる", () => {
		const isVulnerable = parseVersionRange(">= 1.3.14, < 1.4.4");
		expect(isVulnerable("1.3.13")).toBe(false);
		expect(isVulnerable("1.3.14")).toBe(true);
		expect(isVulnerable("1.4.0")).toBe(true);
		expect(isVulnerable("1.4.3")).toBe(true);
		expect(isVulnerable("1.4.4")).toBe(false);
	});

	it("空白なしの条件（<1.4.4）を評価できる", () => {
		const isVulnerable = parseVersionRange("<1.4.4");
		expect(isVulnerable("1.4.3")).toBe(true);
		expect(isVulnerable("1.4.4")).toBe(false);
	});
});

describe("extractBunVersionFromToml", () => {
	it("ダブルクォートで指定されたバージョンを抽出できる", () => {
		const toml = `
[tools]
bun = "1.4.4"
node = "22.0.0"
`;
		expect(extractBunVersionFromToml(toml)).toBe("1.4.4");
	});

	it("シングルクォートで指定されたバージョンを抽出できる", () => {
		const toml = "bun = '1.4.4'";
		expect(extractBunVersionFromToml(toml)).toBe("1.4.4");
	});

	it("前後に空白やコメントがあっても抽出できる", () => {
		const toml = `
# bun version
bun   =   "1.4.4" # latest
`;
		expect(extractBunVersionFromToml(toml)).toBe("1.4.4");
	});

	it("コメント行や xbun などの別名にはマッチしない", () => {
		const toml = `
# bun = "1.0.0"
xbun = "2.0.0"
bun = "1.4.4"
`;
		expect(extractBunVersionFromToml(toml)).toBe("1.4.4");
	});

	it("bun 指定がない場合は null を返す", () => {
		const toml = `
[tools]
node = "22.0.0"
`;
		expect(extractBunVersionFromToml(toml)).toBeNull();
	});
});

describe("checkAdvisories", () => {
	const sampleAdvisories: Advisory[] = [
		{
			ghsa_id: "GHSA-cf8x-9m69-3gg3",
			summary: "HTTP/3 QPACK memory exhaustion",
			severity: "high",
			vulnerabilities: [
				{
					package: { name: "bun" },
					vulnerable_version_range: ">= 1.3.14, < 1.4.4",
					patched_versions: "1.4.4",
				},
			],
		},
		{
			ghsa_id: "GHSA-low-0001",
			summary: "Low risk issue",
			severity: "low",
			vulnerabilities: [
				{
					package: { name: "bun" },
					vulnerable_version_range: "< 1.4.4",
					patched_versions: "1.4.4",
				},
			],
		},
	];

	it("脆弱なバージョン（1.4.3）では High の Advisory を検知して hasCriticalOrHigh=true となる", () => {
		const result = checkAdvisories("1.4.3", sampleAdvisories);
		expect(result.hasCriticalOrHigh).toBe(true);
		expect(
			result.matched.some((a) => a.ghsa_id === "GHSA-cf8x-9m69-3gg3"),
		).toBe(true);
	});

	it("修正版バージョン（1.4.4）では該当なしとなり hasCriticalOrHigh=false となる", () => {
		const result = checkAdvisories("1.4.4", sampleAdvisories);
		expect(result.hasCriticalOrHigh).toBe(false);
		expect(result.matched.length).toBe(0);
	});

	it("package.name が bun 以外の場合は脆弱性があっても無視する", () => {
		const otherAdvisories: Advisory[] = [
			{
				ghsa_id: "GHSA-other-0001",
				summary: "Other package issue",
				severity: "high",
				vulnerabilities: [
					{
						package: { name: "other-tool" },
						vulnerable_version_range: "< 2.0.0",
					},
				],
			},
		];
		const result = checkAdvisories("1.4.3", otherAdvisories);
		expect(result.hasCriticalOrHigh).toBe(false);
		expect(result.matched.length).toBe(0);
	});
});

describe("auditBun (End-to-End & Fail-open)", () => {
	it("High 脆弱性該当時は終了コード 1 を返す", async () => {
		const mockFetch = async () =>
			new Response(
				JSON.stringify([
					{
						ghsa_id: "GHSA-cf8x-9m69-3gg3",
						summary: "HTTP/3 QPACK issue",
						severity: "high",
						vulnerabilities: [
							{
								package: { name: "bun" },
								vulnerable_version_range: "< 1.4.4",
								patched_versions: "1.4.4",
							},
						],
					},
				]),
				{ status: 200 },
			);

		const exitCode = await auditBun({
			version: "1.4.3",
			fetchFn: mockFetch as unknown as typeof fetch,
		});
		expect(exitCode).toBe(1);
	});

	it("脆弱性がない場合は終了コード 0 を返す", async () => {
		const mockFetch = async () =>
			new Response(
				JSON.stringify([
					{
						ghsa_id: "GHSA-cf8x-9m69-3gg3",
						summary: "HTTP/3 QPACK issue",
						severity: "high",
						vulnerabilities: [
							{
								package: { name: "bun" },
								vulnerable_version_range: "< 1.4.4",
								patched_versions: "1.4.4",
							},
						],
					},
				]),
				{ status: 200 },
			);

		const exitCode = await auditBun({
			version: "1.4.4",
			fetchFn: mockFetch as unknown as typeof fetch,
		});
		expect(exitCode).toBe(0);
	});

	it("ネットワークエラー（Fail-open）時は警告を出し終了コード 0 を返す", async () => {
		const mockFetch = async () => {
			throw new Error("Network unreachable (offline)");
		};

		const exitCode = await auditBun({
			version: "1.4.3",
			fetchFn: mockFetch as unknown as typeof fetch,
		});
		expect(exitCode).toBe(0);
	});

	it("API レートリミット（403）時も Fail-open で終了コード 0 を返す", async () => {
		const mockFetch = async () =>
			new Response("API rate limit exceeded", { status: 403 });

		const exitCode = await auditBun({
			version: "1.4.3",
			fetchFn: mockFetch as unknown as typeof fetch,
		});
		expect(exitCode).toBe(0);
	});
});
