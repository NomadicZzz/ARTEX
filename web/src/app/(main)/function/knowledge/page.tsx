"use client";

import * as React from "react";

import Link from "next/link";
import { useSearchParams } from "next/navigation";

import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { KBEntry, KBEntryDetail, KBSource, KBStats, KBSyncRun } from "@/lib/types";

const CLUE = "命中只是检测线索。必须真实触发并取得证据后才能记为漏洞。验证任务创建后保持暂停，确认后才会开始。";

type Filters = {
  q: string;
  kind: string;
  min_severity: string;
  actively_exploited: boolean;
  has_poc: boolean;
  matched_assets_only: boolean;
};

const emptyFilters: Filters = {
  q: "",
  kind: "all",
  min_severity: "all",
  actively_exploited: false,
  has_poc: false,
  matched_assets_only: false,
};

export default function KnowledgePage() {
  return (
    <React.Suspense fallback={null}>
      <KnowledgeInner />
    </React.Suspense>
  );
}

function KnowledgeInner() {
  const search = useSearchParams();
  const [stats, setStats] = React.useState<KBStats | null>(null);
  const [filters, setFilters] = React.useState<Filters>(emptyFilters);
  const [q, setQ] = React.useState("");
  const [items, setItems] = React.useState<KBEntry[]>([]);
  const [total, setTotal] = React.useState(0);
  const [loading, setLoading] = React.useState(true);
  const [detailId, setDetailId] = React.useState<number | null>(null);
  const [createOpen, setCreateOpen] = React.useState(false);
  const [importOpen, setImportOpen] = React.useState(false);

  const loadStats = React.useCallback(() => {
    api.kbStats().then(setStats).catch((e) => toast.error((e as Error).message));
  }, []);

  const loadList = React.useCallback((next: Filters) => {
    setLoading(true);
    api
      .kbEntries(next)
      .then((page) => {
        setItems(page.items ?? []);
        setTotal(page.total);
      })
      .catch((e) => toast.error((e as Error).message))
      .finally(() => setLoading(false));
  }, []);

  React.useEffect(() => {
    loadStats();
    loadList(emptyFilters);
  }, [loadList, loadStats]);

  React.useEffect(() => {
    const raw = search.get("entry");
    if (raw && Number(raw) > 0) setDetailId(Number(raw));
  }, [search]);

  const apply = (patch: Partial<Filters>) => {
    const next = { ...filters, ...patch };
    setFilters(next);
    if (patch.q !== undefined) setQ(patch.q);
    loadList(next);
  };

  return (
    <div className="space-y-4 p-4 md:p-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="font-semibold text-xl">知识库</h1>
          <p className="text-muted-foreground text-sm">{CLUE}</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => setImportOpen(true)}>
            导入
          </Button>
          <Button onClick={() => setCreateOpen(true)}>新建条目</Button>
        </div>
      </div>

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
        <StatCard label="条目" value={stats?.total} onClick={() => apply(emptyFilters)} />
        <StatCard label="在野利用" value={stats?.kev} onClick={() => apply({ ...emptyFilters, actively_exploited: true })} />
        <StatCard label="方法 / 清单" value={stats?.methodology} onClick={() => apply({ ...emptyFilters, kind: "methodology" })} />
        <StatCard label="含 PoC" value={stats?.with_poc} onClick={() => apply({ ...emptyFilters, has_poc: true })} />
        <StatCard
          label="命中存量资产的条目"
          value={stats?.matched_entries}
          onClick={() => apply({ ...emptyFilters, matched_assets_only: true })}
        />
        <StatCard label="被命中的资产" value={stats?.matched_assets} />
      </div>

      <Tabs defaultValue="search">
        <TabsList>
          <TabsTrigger value="search">检索与资产碰撞</TabsTrigger>
          <TabsTrigger value="sources">情报源与同步日志</TabsTrigger>
        </TabsList>
        <TabsContent value="search" className="mt-4 space-y-3">
          <div className="flex flex-wrap gap-2">
            <Input
              value={q}
              placeholder="CVE、产品或关键词"
              className="max-w-sm"
              onChange={(e) => setQ(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") apply({ q });
              }}
            />
            <select className="h-9 rounded-md border bg-background px-2 text-sm" value={filters.kind} onChange={(e) => apply({ kind: e.target.value })}>
              <option value="all">全部类型</option>
              <option value="cve">CVE</option>
              <option value="poc">PoC</option>
              <option value="methodology">方法</option>
              <option value="checklist">清单</option>
            </select>
            <select
              className="h-9 rounded-md border bg-background px-2 text-sm"
              value={filters.min_severity}
              onChange={(e) => apply({ min_severity: e.target.value })}
            >
              <option value="all">全部等级</option>
              <option value="critical">严重及以上</option>
              <option value="high">高危及以上</option>
              <option value="medium">中危及以上</option>
              <option value="low">低危及以上</option>
            </select>
            <Button variant="secondary" onClick={() => apply({ q })}>
              搜索
            </Button>
            <label className="flex items-center gap-2 text-sm">
              <Switch checked={filters.matched_assets_only} onCheckedChange={(v) => apply({ matched_assets_only: v })} />
              仅看命中存量资产
            </label>
            <label className="flex items-center gap-2 text-sm">
              <Switch checked={filters.actively_exploited} onCheckedChange={(v) => apply({ actively_exploited: v })} />
              仅看 KEV 在野利用
            </label>
            <label className="flex items-center gap-2 text-sm">
              <Switch checked={filters.has_poc} onCheckedChange={(v) => apply({ has_poc: v })} />
              仅看含 PoC
            </label>
          </div>
          <Card>
            <CardHeader className="py-3">
              <CardTitle className="text-sm">{loading ? "加载中…" : `${total} 条`}</CardTitle>
            </CardHeader>
            <CardContent className="px-0">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>标题</TableHead>
                    <TableHead>编号</TableHead>
                    <TableHead>类型</TableHead>
                    <TableHead>等级</TableHead>
                    <TableHead>CVSS</TableHead>
                    <TableHead>来源</TableHead>
                    <TableHead>产品</TableHead>
                    <TableHead>命中资产</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {items.map((item) => (
                    <TableRow key={item.id} className="cursor-pointer" onClick={() => setDetailId(item.id)}>
                      <TableCell>
                        <div className="font-medium">{item.title}</div>
                        <div className="text-muted-foreground text-xs">{item.summary}</div>
                      </TableCell>
                      <TableCell className="font-mono text-xs">{item.external_id || "—"}</TableCell>
                      <TableCell className="text-xs">{item.kind}</TableCell>
                      <TableCell>
                        <Badge variant={item.actively_exploited ? "destructive" : "secondary"}>{item.severity}</Badge>
                      </TableCell>
                      <TableCell className="text-xs tabular-nums">{item.cvss_score ?? "—"}</TableCell>
                      <TableCell className="text-xs">{(item.source_keys ?? []).join(" + ") || "—"}</TableCell>
                      <TableCell className="text-xs">{(item.products ?? []).slice(0, 3).join(", ")}</TableCell>
                      <TableCell>{item.matched_asset_count ? `命中存量资产 (${item.matched_asset_count})` : "—"}</TableCell>
                    </TableRow>
                  ))}
                  {!loading && items.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={8} className="text-muted-foreground">
                        没有条目
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>
        <TabsContent value="sources" className="mt-4">
          <SourcesPanel />
        </TabsContent>
      </Tabs>

      <EntrySheet id={detailId} onClose={() => setDetailId(null)} onChanged={loadStats} />
      <EntryDialog
        open={createOpen}
        title="新建条目"
        onClose={() => setCreateOpen(false)}
        onSubmit={async (body) => {
          await api.kbCreateEntry({ ...body, origin: "manual", kind: body.kind || "methodology" });
          toast.success("已写入");
          setCreateOpen(false);
          loadList(filters);
          loadStats();
        }}
      />
      <ImportDialog
        open={importOpen}
        onClose={() => setImportOpen(false)}
        onDone={() => {
          setImportOpen(false);
          loadList(filters);
          loadStats();
        }}
      />
    </div>
  );
}

function StatCard({ label, value, onClick }: { label: string; value?: number; onClick?: () => void }) {
  return (
    <button type="button" onClick={onClick} className="text-left" disabled={!onClick}>
      <Card className={onClick ? "hover:bg-muted/40" : ""}>
        <CardHeader className="pb-1">
          <CardTitle className="text-muted-foreground text-xs font-normal">{label}</CardTitle>
        </CardHeader>
        <CardContent className="text-2xl font-semibold tabular-nums">{value ?? "—"}</CardContent>
      </Card>
    </button>
  );
}

function EntrySheet({ id, onClose, onChanged }: { id: number | null; onClose: () => void; onChanged: () => void }) {
  const [detail, setDetail] = React.useState<KBEntryDetail | null>(null);
  const [picked, setPicked] = React.useState<number[]>([]);
  const [edit, setEdit] = React.useState(false);
  const [busy, setBusy] = React.useState(false);

  React.useEffect(() => {
    if (!id) {
      setDetail(null);
      setPicked([]);
      return;
    }
    api
      .kbEntry(id)
      .then((d) => {
        setDetail(d);
        setPicked((d.matched_assets ?? []).map((a) => a.asset_id));
      })
      .catch((e) => toast.error((e as Error).message));
  }, [id]);

  const entry = detail?.entry;
  const reload = () => {
    if (!id) return;
    api.kbEntry(id).then(setDetail).catch((e) => toast.error((e as Error).message));
    onChanged();
  };

  return (
    <Sheet open={id != null} onOpenChange={(open) => !open && onClose()}>
      <SheetContent className="w-full overflow-y-auto sm:max-w-2xl">
        {!entry ? (
          <p className="text-muted-foreground text-sm">加载中…</p>
        ) : (
          <>
            <SheetHeader>
              <SheetTitle>{entry.title}</SheetTitle>
              <SheetDescription>
                {entry.external_id || entry.nkey} · {entry.severity}
                {entry.actively_exploited ? " · 在野利用" : ""}
              </SheetDescription>
            </SheetHeader>
            <div className="mt-4 space-y-4 text-sm">
              <p className="text-muted-foreground">{CLUE}</p>
              <p className="whitespace-pre-wrap">{entry.summary}</p>
              {entry.affected_versions && <p>受影响版本：{entry.affected_versions}</p>}
              <section>
                <h3 className="mb-1 font-medium">检测思路</h3>
                <pre className="max-h-64 overflow-auto whitespace-pre-wrap rounded-md bg-muted p-3 text-xs">{entry.detection_guide || "（空）"}</pre>
              </section>
              {entry.remediation && (
                <section>
                  <h3 className="mb-1 font-medium">修复建议</h3>
                  <pre className="max-h-48 overflow-auto whitespace-pre-wrap rounded-md bg-muted p-3 text-xs">{entry.remediation}</pre>
                </section>
              )}
              {entry.poc_snippet && (
                <section>
                  <div className="mb-1 flex items-center justify-between">
                    <h3 className="font-medium">PoC 片段</h3>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => {
                        void navigator.clipboard.writeText(entry.poc_snippet || "");
                        toast.success("已复制");
                      }}
                    >
                      复制
                    </Button>
                  </div>
                  <pre className="max-h-64 overflow-auto whitespace-pre-wrap rounded-md bg-muted p-3 text-xs">{entry.poc_snippet}</pre>
                </section>
              )}
              <section>
                <h3 className="mb-2 font-medium">命中存量资产 ({detail.matched_assets?.length ?? 0})</h3>
                <div className="space-y-1">
                  {(detail.matched_assets ?? []).map((asset) => (
                    <label key={asset.asset_id} className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={picked.includes(asset.asset_id)}
                        onChange={(e) =>
                          setPicked((cur) =>
                            e.target.checked ? [...cur, asset.asset_id] : cur.filter((x) => x !== asset.asset_id),
                          )
                        }
                      />
                      <span>
                        {asset.label} <span className="text-muted-foreground">{(asset.matched_tech ?? []).join(", ")}</span>
                      </span>
                    </label>
                  ))}
                  {(detail.matched_assets ?? []).length === 0 && <p className="text-muted-foreground">没有命中资产</p>}
                </div>
              </section>
              {(detail.related_findings ?? []).length > 0 && (
                <section>
                  <h3 className="mb-1 font-medium">关联漏洞</h3>
                  {(detail.related_findings ?? []).map((f) => (
                    <Link key={f.id} href={`/function/findings/detail?id=${f.id}`} className="block text-primary hover:underline">
                      {f.name || f.vulnclass} · {f.severity}
                    </Link>
                  ))}
                </section>
              )}
              <div className="flex flex-wrap gap-2">
                <Button
                  disabled={busy}
                  onClick={async () => {
                    if (picked.length === 0) {
                      toast.error("至少选择一个资产");
                      return;
                    }
                    setBusy(true);
                    try {
                      const res = await api.kbCreateVerifyTask(entry.id, picked);
                      toast.success(res.message);
                    } catch (e) {
                      toast.error((e as Error).message);
                    } finally {
                      setBusy(false);
                    }
                  }}
                >
                  创建验证任务
                </Button>
                <Button
                  variant="outline"
                  disabled={busy}
                  onClick={async () => {
                    setBusy(true);
                    try {
                      await api.kbDistillEntry(entry.id);
                      toast.success("已整理检测思路");
                      reload();
                    } catch (e) {
                      toast.error((e as Error).message);
                    } finally {
                      setBusy(false);
                    }
                  }}
                >
                  AI 整理
                </Button>
                <Button variant="outline" onClick={() => setEdit(true)}>
                  编辑
                </Button>
              </div>
            </div>
            <EntryDialog
              open={edit}
              title="编辑条目"
              initial={entry}
              onClose={() => setEdit(false)}
              onSubmit={async (body) => {
                await api.kbUpdateEntry(entry.id, body);
                toast.success("已保存");
                setEdit(false);
                reload();
              }}
            />
          </>
        )}
      </SheetContent>
    </Sheet>
  );
}

function EntryDialog({
  open,
  title,
  initial,
  onClose,
  onSubmit,
}: {
  open: boolean;
  title: string;
  initial?: Partial<KBEntry>;
  onClose: () => void;
  onSubmit: (body: Partial<KBEntry>) => Promise<void>;
}) {
  const [titleText, setTitleText] = React.useState("");
  const [summary, setSummary] = React.useState("");
  const [guide, setGuide] = React.useState("");
  const [severity, setSeverity] = React.useState("info");
  const [products, setProducts] = React.useState("");
  const [kind, setKind] = React.useState("methodology");

  React.useEffect(() => {
    if (!open) return;
    setTitleText(initial?.title ?? "");
    setSummary(initial?.summary ?? "");
    setGuide(initial?.detection_guide ?? "");
    setSeverity(initial?.severity || "info");
    setProducts((initial?.products ?? []).join(", "));
    setKind(initial?.kind || "methodology");
  }, [open, initial]);

  return (
    <Dialog open={open} onOpenChange={(next) => !next && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
        </DialogHeader>
        <div className="space-y-3">
          <Label>标题</Label>
          <Input value={titleText} onChange={(e) => setTitleText(e.target.value)} />
          <Label>摘要</Label>
          <Textarea value={summary} onChange={(e) => setSummary(e.target.value)} />
          <Label>检测思路</Label>
          <Textarea value={guide} onChange={(e) => setGuide(e.target.value)} />
          <Label>产品（逗号分隔）</Label>
          <Input value={products} onChange={(e) => setProducts(e.target.value)} />
          <div className="flex gap-2">
            <select className="h-9 rounded-md border bg-background px-2 text-sm" value={kind} onChange={(e) => setKind(e.target.value)}>
              <option value="methodology">方法</option>
              <option value="checklist">清单</option>
              <option value="poc">PoC</option>
              <option value="cve">CVE</option>
            </select>
            <select className="h-9 rounded-md border bg-background px-2 text-sm" value={severity} onChange={(e) => setSeverity(e.target.value)}>
              <option value="info">info</option>
              <option value="low">low</option>
              <option value="medium">medium</option>
              <option value="high">high</option>
              <option value="critical">critical</option>
            </select>
          </div>
        </div>
        <DialogFooter>
          <Button
            onClick={() =>
              onSubmit({
                title: titleText,
                summary,
                detection_guide: guide,
                severity,
                kind,
                products: products.split(",").map((s) => s.trim()).filter(Boolean),
                enabled: true,
              }).catch((e) => toast.error((e as Error).message))
            }
          >
            保存
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function ImportDialog({ open, onClose, onDone }: { open: boolean; onClose: () => void; onDone: () => void }) {
  const [format, setFormat] = React.useState("markdown");
  const [content, setContent] = React.useState("");
  return (
    <Dialog open={open} onOpenChange={(next) => !next && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>导入 Markdown / JSON</DialogTitle>
        </DialogHeader>
        <select className="h-9 rounded-md border bg-background px-2 text-sm" value={format} onChange={(e) => setFormat(e.target.value)}>
          <option value="markdown">Markdown（按一级标题拆分）</option>
          <option value="json">JSON</option>
        </select>
        <Textarea value={content} onChange={(e) => setContent(e.target.value)} className="min-h-40" />
        <DialogFooter>
          <Button
            onClick={async () => {
              try {
                const res = await api.kbImport({ format, content });
                toast.success(`导入 ${res.imported} 条`);
                onDone();
              } catch (e) {
                toast.error((e as Error).message);
              }
            }}
          >
            导入
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function cfgStr(cfg: Record<string, unknown> | undefined, key: string): string {
  const value = cfg?.[key];
  if (typeof value === "string" || typeof value === "number") return String(value);
  return "";
}

function runDuration(run: KBSyncRun): string {
  if (!run.finished_at) return "进行中";
  const ms = new Date(run.finished_at).getTime() - new Date(run.started_at).getTime();
  if (!Number.isFinite(ms) || ms < 0) return "—";
  const sec = Math.round(ms / 1000);
  if (sec < 60) return `${sec} 秒`;
  return `${Math.floor(sec / 60)} 分 ${sec % 60} 秒`;
}

function SourcesPanel() {
  const [sources, setSources] = React.useState<KBSource[]>([]);
  const [runs, setRuns] = React.useState<KBSyncRun[]>([]);
  const [createOpen, setCreateOpen] = React.useState(false);

  const load = React.useCallback(() => {
    api
      .kbSources()
      .then((res) => setSources(res.sources ?? []))
      .catch((e) => toast.error((e as Error).message));
    api
      .kbSyncRuns()
      .then((res) => setRuns(res.runs ?? []))
      .catch((e) => toast.error((e as Error).message));
  }, []);

  React.useEffect(() => {
    load();
  }, [load]);

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="flex-row items-center justify-between">
          <CardTitle className="text-sm">情报源</CardTitle>
          <Button size="sm" variant="outline" onClick={() => setCreateOpen(true)}>
            添加自定义源
          </Button>
        </CardHeader>
        <CardContent className="space-y-3">
          {sources.map((src) => (
            <SourceCard key={src.id} src={src} onChanged={load} />
          ))}
        </CardContent>
      </Card>
      <CreateSourceDialog
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        onDone={() => {
          setCreateOpen(false);
          load();
        }}
      />
      <Card>
        <CardHeader>
          <CardTitle className="text-sm">同步日志</CardTitle>
        </CardHeader>
        <CardContent className="px-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>源</TableHead>
                <TableHead>状态</TableHead>
                <TableHead>拉取 / 新增 / 合并</TableHead>
                <TableHead>耗时</TableHead>
                <TableHead>错误</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {runs.map((run) => (
                <TableRow key={run.id}>
                  <TableCell>{run.source_key || run.source_id}</TableCell>
                  <TableCell>{run.status}</TableCell>
                  <TableCell>
                    {run.fetched_count} / {run.upserted_count} / {run.merged_count}
                  </TableCell>
                  <TableCell className="text-xs">{runDuration(run)}</TableCell>
                  <TableCell className="text-xs">{run.error}</TableCell>
                </TableRow>
              ))}
              {runs.length === 0 && (
                <TableRow>
                  <TableCell colSpan={5} className="text-muted-foreground">
                    还没有同步记录
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}

function SourceCard({ src, onChanged }: { src: KBSource; onChanged: () => void }) {
  const [open, setOpen] = React.useState(false);
  const [hours, setHours] = React.useState("24");
  const [minSev, setMinSev] = React.useState("");
  const [sinceDays, setSinceDays] = React.useState("");
  const [feedURL, setFeedURL] = React.useState("");
  const [repoURL, setRepoURL] = React.useState("");
  const [branch, setBranch] = React.useState("main");
  const [repoPath, setRepoPath] = React.useState("");
  const [pageLimit, setPageLimit] = React.useState("");
  const [distill, setDistill] = React.useState(false);
  const [apiKey, setApiKey] = React.useState("");
  const windowed = src.kind === "nvd" || src.kind === "ghsa";
  const feed = src.kind === "avd" || src.kind === "seebug" || src.kind === "rss";
  const git = src.kind === "git_markdown";

  React.useEffect(() => {
    setHours(String(Math.max(1, Math.round((src.sync_interval_sec || 86400) / 3600))));
    setMinSev(cfgStr(src.config, "min_severity") || "high");
    setSinceDays(cfgStr(src.config, "since_days") || "120");
    setFeedURL(cfgStr(src.config, "feed_url"));
    setRepoURL(cfgStr(src.config, "repo_url"));
    setBranch(cfgStr(src.config, "branch") || "main");
    setRepoPath(cfgStr(src.config, "path"));
    setPageLimit(cfgStr(src.config, "page_limit") || "3");
    setDistill(src.config?.distill === true);
    setApiKey("");
  }, [src]);

  const save = async () => {
    const config: Record<string, unknown> = { ...(src.config ?? {}) };
    delete config.api_key;
    config.distill = distill;
    if (windowed) {
      config.min_severity = minSev || "high";
      config.since_days = Number(sinceDays) || 120;
    }
    if (feed) config.feed_url = feedURL.trim();
    if (src.kind === "avd") config.page_limit = Number(pageLimit) || 3;
    if (git) {
      config.repo_url = repoURL.trim();
      config.branch = branch.trim() || "main";
      config.path = repoPath.trim();
    }
    if (apiKey.trim()) config.api_key = apiKey.trim();
    try {
      await api.kbUpdateSource(src.id, {
        name: src.name,
        enabled: src.enabled,
        sync_interval_sec: Math.max(1, Number(hours) || 24) * 3600,
        config,
      });
      toast.success("已保存情报源配置");
      onChanged();
    } catch (e) {
      toast.error((e as Error).message);
    }
  };

  return (
    <div className="rounded-md border p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <div className="font-medium">{src.name}</div>
          <div className="text-muted-foreground text-xs">
            {src.kind} · {src.entry_count} 条 · {src.last_status || "未同步"}
            {src.last_error ? ` · ${src.last_error}` : ""}
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Switch
            checked={src.enabled}
            onCheckedChange={async (enabled) => {
              try {
                await api.kbUpdateSource(src.id, {
                  name: src.name,
                  enabled,
                  sync_interval_sec: src.sync_interval_sec,
                  config: src.config,
                });
                onChanged();
              } catch (e) {
                toast.error((e as Error).message);
              }
            }}
          />
          <Button size="sm" variant="outline" onClick={() => setOpen((v) => !v)}>
            配置
          </Button>
          <Button
            size="sm"
            variant="outline"
            onClick={async () => {
              try {
                const res = await api.kbSyncSource(src.id);
                toast.success(res.status === "running" ? "已在同步" : "已开始同步");
              } catch (e) {
                toast.error((e as Error).message);
              }
            }}
          >
            同步
          </Button>
          {!src.builtin && (
            <Button
              size="sm"
              variant="ghost"
              onClick={async () => {
                try {
                  await api.kbDeleteSource(src.id);
                  onChanged();
                } catch (e) {
                  toast.error((e as Error).message);
                }
              }}
            >
              删除
            </Button>
          )}
        </div>
      </div>
      {open && (
        <div className="mt-3 grid gap-2 sm:grid-cols-2">
          <label className="text-xs">
            同步周期（小时）
            <Input value={hours} onChange={(e) => setHours(e.target.value)} />
          </label>
          {windowed && (
            <>
              <label className="text-xs">
                最低等级
                <select className="mt-1 h-9 w-full rounded-md border bg-background px-2 text-sm" value={minSev} onChange={(e) => setMinSev(e.target.value)}>
                  <option value="critical">critical</option>
                  <option value="high">high</option>
                  <option value="medium">medium</option>
                  <option value="low">low</option>
                </select>
              </label>
              <label className="text-xs">
                时间窗口（天，最多 119）
                <Input value={sinceDays} onChange={(e) => setSinceDays(e.target.value)} />
              </label>
            </>
          )}
          {feed && (
            <label className="text-xs sm:col-span-2">
              Feed URL
              <Input value={feedURL} onChange={(e) => setFeedURL(e.target.value)} />
            </label>
          )}
          {src.kind === "avd" && (
            <label className="text-xs">
              列表页数
              <Input value={pageLimit} onChange={(e) => setPageLimit(e.target.value)} />
            </label>
          )}
          {git && (
            <>
              <label className="text-xs sm:col-span-2">
                仓库 URL
                <Input value={repoURL} onChange={(e) => setRepoURL(e.target.value)} placeholder="https://github.com/org/repo" />
              </label>
              <label className="text-xs">
                分支
                <Input value={branch} onChange={(e) => setBranch(e.target.value)} />
              </label>
              <label className="text-xs">
                路径
                <Input value={repoPath} onChange={(e) => setRepoPath(e.target.value)} />
              </label>
            </>
          )}
          {(windowed || src.kind === "nuclei") && (
            <label className="text-xs sm:col-span-2">
              API Key{src.api_key_set ? "（已设置，留空则保留）" : ""}
              <Input type="password" value={apiKey} onChange={(e) => setApiKey(e.target.value)} autoComplete="off" />
            </label>
          )}
          <label className="flex items-center gap-2 text-xs sm:col-span-2">
            <Switch checked={distill} onCheckedChange={setDistill} />
            同步后用模型整理空的检测思路（默认关闭）
          </label>
          <div>
            <Button size="sm" onClick={() => void save()}>
              保存配置
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}

function CreateSourceDialog({ open, onClose, onDone }: { open: boolean; onClose: () => void; onDone: () => void }) {
  const [key, setKey] = React.useState("");
  const [name, setName] = React.useState("");
  const [kind, setKind] = React.useState("git_markdown");
  const [target, setTarget] = React.useState("");
  return (
    <Dialog open={open} onOpenChange={(next) => !next && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>添加自定义源</DialogTitle>
        </DialogHeader>
        <div className="space-y-3">
          <Label>标识（字母、数字、下划线）</Label>
          <Input value={key} onChange={(e) => setKey(e.target.value)} />
          <Label>名称</Label>
          <Input value={name} onChange={(e) => setName(e.target.value)} />
          <select className="h-9 rounded-md border bg-background px-2 text-sm" value={kind} onChange={(e) => setKind(e.target.value)}>
            <option value="git_markdown">Git Markdown</option>
            <option value="rss">RSS</option>
          </select>
          <Label>{kind === "rss" ? "Feed URL" : "仓库 URL"}</Label>
          <Input value={target} onChange={(e) => setTarget(e.target.value)} />
        </div>
        <DialogFooter>
          <Button
            onClick={async () => {
              try {
                const config = kind === "rss" ? { feed_url: target.trim() } : { repo_url: target.trim(), branch: "main", path: "" };
                await api.kbCreateSource({
                  key: key.trim(),
                  name: name.trim() || key.trim(),
                  kind,
                  enabled: kind === "rss" || target.trim() !== "",
                  sync_interval_sec: 86400,
                  config,
                });
                toast.success("已添加");
                onDone();
              } catch (e) {
                toast.error((e as Error).message);
              }
            }}
          >
            添加
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
