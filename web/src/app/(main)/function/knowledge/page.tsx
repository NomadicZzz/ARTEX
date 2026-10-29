"use client";

import * as React from "react";

import Link from "next/link";
import { useSearchParams } from "next/navigation";

import { BoxesIcon, BugIcon, CrosshairIcon, LibraryIcon, ListChecksIcon, SearchIcon, ShieldAlertIcon, UploadIcon } from "lucide-react";
import { toast } from "sonner";

import { CopyButton } from "@/components/copy-button";
import { StatusBadge } from "@/components/status-badge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Field, FieldGroup, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { InputGroup, InputGroupAddon, InputGroupInput } from "@/components/ui/input-group";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { TablePagination } from "@/components/table-pagination";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";
import type { KBEntry, KBEntryDetail, KBReportParseResp, KBSource, KBStats, KBSyncRun } from "@/lib/types";

const CLUE = "命中只是检测线索。必须真实触发并取得证据后才能记为漏洞。验证任务创建后保持暂停，确认后才会开始。";

const KIND_LABEL: Record<string, string> = {
  cve: "漏洞",
  poc: "PoC",
  methodology: "方法",
  checklist: "清单",
};

const SOURCE_KIND: Record<string, string> = {
  cisa_kev: "KEV",
  kev: "KEV",
  nuclei: "Nuclei",
  nvd: "NVD",
  ghsa: "GHSA",
  avd: "AVD",
  seebug: "Seebug",
  rss: "RSS",
  git_markdown: "Git Markdown",
};

const SOURCE_KEY: Record<string, string> = {
  cisa_kev: "KEV",
  nuclei_templates: "Nuclei",
  nvd_cve: "NVD",
  github_ghsa: "GHSA",
  aliyun_avd: "AVD",
  seebug_rss: "Seebug",
  custom_git_kb: "Git",
};

function kindLabel(kind: string) {
  return KIND_LABEL[kind] || kind;
}

function sourceLabel(key: string) {
  return SOURCE_KEY[key] || SOURCE_KIND[key] || key;
}

function syncStatusLabel(status: string) {
  if (!status) return "未同步";
  if (status === "ok" || status === "success") return "成功";
  if (status === "error" || status === "failed") return "失败";
  if (status === "running" || status === "started") return "进行中";
  return status;
}

function SyncStatusBadge({ status }: { status: string }) {
  const failed = status === "error" || status === "failed";
  return <Badge variant={failed ? "destructive" : status ? "secondary" : "outline"}>{syncStatusLabel(status)}</Badge>;
}

function SeverityMark({ value }: { value: string }) {
  if (!value || value === "info") return <Badge variant="outline">提示</Badge>;
  return <StatusBadge domain="severity" value={value} dot />;
}

type Filters = {
  q: string;
  kind: string;
  min_severity: string;
  actively_exploited: boolean;
  has_poc: boolean;
  matched_assets_only: boolean;
  source: string;
};

const emptyFilters: Filters = {
  q: "",
  kind: "all",
  min_severity: "all",
  actively_exploited: false,
  has_poc: false,
  matched_assets_only: false,
  source: "",
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
  const [page, setPage] = React.useState(1);
  const [pageSize, setPageSize] = React.useState(20);
  const [loading, setLoading] = React.useState(true);
  const [detailId, setDetailId] = React.useState<number | null>(null);
  const [createOpen, setCreateOpen] = React.useState(false);
  const [importOpen, setImportOpen] = React.useState(false);

  const loadStats = React.useCallback(() => {
    api.kbStats().then(setStats).catch((e) => toast.error((e as Error).message));
  }, []);

  const loadList = React.useCallback((next: Filters, pageNum: number, size: number) => {
    setLoading(true);
    api
      .kbEntries({ ...next, limit: size, offset: (pageNum - 1) * size })
      .then((result) => {
        setItems(result.items ?? []);
        setTotal(result.total);
      })
      .catch((e) => toast.error((e as Error).message))
      .finally(() => setLoading(false));
  }, []);

  React.useEffect(() => {
    loadStats();
    loadList(emptyFilters, 1, 20);
  }, [loadList, loadStats]);

  React.useEffect(() => {
    const raw = search.get("entry");
    if (raw && Number(raw) > 0) setDetailId(Number(raw));
  }, [search]);

  const apply = (patch: Partial<Filters>) => {
    const next = { ...filters, ...patch };
    setFilters(next);
    if (patch.q !== undefined) setQ(patch.q);
    setPage(1);
    loadList(next, 1, pageSize);
  };

  const changePage = (nextPage: number) => {
    setPage(nextPage);
    loadList(filters, nextPage, pageSize);
  };

  const changePageSize = (size: number) => {
    setPageSize(size);
    setPage(1);
    loadList(filters, 1, size);
  };

  return (
    <div className="flex min-w-0 flex-1 flex-col gap-4 md:gap-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="min-w-0">
          <h1 className="font-semibold text-xl tracking-tight">知识库</h1>
          <p className="text-muted-foreground text-sm">{CLUE}</p>
        </div>
        <div className="flex gap-2">
          <Button size="sm" variant="outline" onClick={() => setImportOpen(true)}>
            导入
          </Button>
          <Button size="sm" onClick={() => setCreateOpen(true)}>
            新建条目
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-6">
        <StatCard icon={<LibraryIcon className="size-5" aria-hidden />} label="条目" value={stats?.total} onClick={() => apply(emptyFilters)} />
        <StatCard
          icon={<ShieldAlertIcon className="size-5" aria-hidden />}
          label="在野利用"
          value={stats?.kev}
          tone="text-rose-600"
          onClick={() => apply({ ...emptyFilters, actively_exploited: true })}
        />
        <StatCard
          icon={<ListChecksIcon className="size-5" aria-hidden />}
          label="方法 / 清单"
          value={stats?.methodology}
          onClick={() => apply({ ...emptyFilters, kind: "methodology" })}
        />
        <StatCard
          icon={<BugIcon className="size-5" aria-hidden />}
          label="含 PoC"
          value={stats?.with_poc}
          tone="text-amber-500"
          onClick={() => apply({ ...emptyFilters, has_poc: true })}
        />
        <StatCard
          icon={<CrosshairIcon className="size-5" aria-hidden />}
          label="命中存量资产"
          value={stats?.matched_entries}
          onClick={() => apply({ ...emptyFilters, matched_assets_only: true })}
        />
        <StatCard icon={<BoxesIcon className="size-5" aria-hidden />} label="被命中的资产" value={stats?.matched_assets} />
      </div>

      <Tabs defaultValue="search" className="min-w-0 gap-4">
        <TabsList>
          <TabsTrigger value="search">检索与资产碰撞</TabsTrigger>
          <TabsTrigger value="sources">情报源与同步日志</TabsTrigger>
        </TabsList>
        <TabsContent value="search" className="min-w-0 space-y-4">
          <div className="flex flex-wrap items-center gap-2">
            <InputGroup className="w-full sm:w-72">
              <InputGroupInput
                type="search"
                value={q}
                placeholder="CVE、产品或关键词"
                aria-label="检索知识库"
                onChange={(e) => setQ(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") apply({ q });
                }}
              />
              <InputGroupAddon>
                <SearchIcon aria-hidden />
              </InputGroupAddon>
            </InputGroup>
            <Select value={filters.kind} onValueChange={(value) => apply({ kind: value })}>
              <SelectTrigger className="w-36">
                <SelectValue placeholder="类型" />
              </SelectTrigger>
              <SelectContent>
                <SelectGroup>
                  <SelectItem value="all">全部类型</SelectItem>
                  <SelectItem value="cve">漏洞</SelectItem>
                  <SelectItem value="poc">PoC</SelectItem>
                  <SelectItem value="methodology">方法</SelectItem>
                  <SelectItem value="checklist">清单</SelectItem>
                </SelectGroup>
              </SelectContent>
            </Select>
            <Select value={filters.min_severity} onValueChange={(value) => apply({ min_severity: value })}>
              <SelectTrigger className="w-36">
                <SelectValue placeholder="等级" />
              </SelectTrigger>
              <SelectContent>
                <SelectGroup>
                  <SelectItem value="all">全部等级</SelectItem>
                  <SelectItem value="critical">严重及以上</SelectItem>
                  <SelectItem value="high">高危及以上</SelectItem>
                  <SelectItem value="medium">中危及以上</SelectItem>
                  <SelectItem value="low">低危及以上</SelectItem>
                </SelectGroup>
              </SelectContent>
            </Select>
            <Button size="sm" variant="outline" onClick={() => apply({ q })}>
              搜索
            </Button>
            <label className="flex items-center gap-2 text-muted-foreground text-sm">
              <Switch checked={filters.matched_assets_only} onCheckedChange={(v) => apply({ matched_assets_only: v })} />
              仅看命中存量资产
            </label>
            <label className="flex items-center gap-2 text-muted-foreground text-sm">
              <Switch checked={filters.actively_exploited} onCheckedChange={(v) => apply({ actively_exploited: v })} />
              仅看在野利用
            </label>
            <label className="flex items-center gap-2 text-muted-foreground text-sm">
              <Switch checked={filters.has_poc} onCheckedChange={(v) => apply({ has_poc: v })} />
              仅看含 PoC
            </label>
            <label className="flex items-center gap-2 text-muted-foreground text-sm">
              <Switch
                checked={filters.source === "finding_distilled"}
                onCheckedChange={(v) => apply({ source: v ? "finding_distilled" : "" })}
              />
              实战漏洞沉淀
            </label>
          </div>
          <Card className="min-w-0 gap-0 overflow-hidden py-0">
            <CardContent className="px-0">
              <Table className="table-fixed">
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-[34%]">标题</TableHead>
                    <TableHead className="w-[14%]">编号</TableHead>
                    <TableHead className="w-[8%]">类型</TableHead>
                    <TableHead className="w-[10%]">等级</TableHead>
                    <TableHead className="w-[8%]">CVSS</TableHead>
                    <TableHead className="w-[12%]">来源</TableHead>
                    <TableHead>产品</TableHead>
                    <TableHead className="w-[8%]">命中</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {items.map((item) => {
                    const products = (item.products ?? []).filter(Boolean);
                    const sources = item.source_keys ?? [];
                    return (
                      <TableRow key={item.id} className="cursor-pointer" onClick={() => setDetailId(item.id)}>
                        <TableCell className="overflow-hidden">
                          <div className="truncate font-medium" title={item.title}>
                            {item.title}
                          </div>
                          <div className="truncate text-muted-foreground text-xs" title={item.summary}>
                            {item.summary}
                          </div>
                        </TableCell>
                        <TableCell className="overflow-hidden">
                          <code className="block truncate rounded bg-muted px-1.5 py-0.5 font-mono text-xs text-muted-foreground" title={item.external_id || item.nkey}>
                            {item.external_id || "—"}
                          </code>
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline">{kindLabel(item.kind)}</Badge>
                        </TableCell>
                        <TableCell>
                          <SeverityMark value={item.severity} />
                        </TableCell>
                        <TableCell className="text-xs tabular-nums">{item.cvss_score ?? "—"}</TableCell>
                        <TableCell className="overflow-hidden text-xs">
                          <span className="block truncate" title={sources.join(" · ")}>
                            {sources.map(sourceLabel).join(" · ") || "—"}
                          </span>
                        </TableCell>
                        <TableCell className="overflow-hidden text-xs">
                          <span className="block truncate" title={products.join("、")}>
                            {products.slice(0, 2).join("、") || "—"}
                            {products.length > 2 ? ` +${products.length - 2}` : ""}
                          </span>
                        </TableCell>
                        <TableCell>
                          {item.matched_asset_count ? (
                            <Badge variant="outline">{item.matched_asset_count}</Badge>
                          ) : (
                            <span className="text-muted-foreground">—</span>
                          )}
                        </TableCell>
                      </TableRow>
                    );
                  })}
                  {!loading && items.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={8} className="py-10 text-center text-muted-foreground">
                        没有条目
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
              <TablePagination
                page={page}
                pageSize={pageSize}
                total={total}
                onPageChange={changePage}
                onPageSizeChange={changePageSize}
                pageSizeOptions={[10, 20, 50, 100]}
              />
            </CardContent>
          </Card>
        </TabsContent>
        <TabsContent value="sources">
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
          loadList(filters, page, pageSize);
          loadStats();
        }}
      />
      <ImportDialog
        open={importOpen}
        onClose={() => setImportOpen(false)}
        onDone={() => {
          setImportOpen(false);
          loadList(filters, page, pageSize);
          loadStats();
        }}
      />
    </div>
  );
}

function StatCard({
  icon,
  label,
  value,
  tone,
  onClick,
}: {
  icon: React.ReactNode;
  label: string;
  value?: number;
  tone?: string;
  onClick?: () => void;
}) {
  const card = (
    <Card className={cn("gap-1 py-4", onClick && "transition-colors hover:bg-muted/40")}>
      <CardHeader className="px-4">
        <CardDescription>{label}</CardDescription>
        <CardTitle className={cn("flex items-center gap-2 text-2xl tabular-nums", tone)}>
          {icon}
          {value ?? "—"}
        </CardTitle>
      </CardHeader>
    </Card>
  );
  if (!onClick) return card;
  return (
    <button type="button" onClick={onClick} className="text-left">
      {card}
    </button>
  );
}

function MetaRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-3 py-2.5">
      <span className="shrink-0 pt-0.5 text-muted-foreground text-xs">{label}</span>
      <div className="flex min-w-0 flex-col items-end gap-1 text-right text-sm">{children}</div>
    </div>
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
  const assets = detail?.matched_assets ?? [];
  const findings = detail?.related_findings ?? [];
  const products = entry?.products ?? [];
  const sources = entry?.source_keys ?? [];
  const references = entry?.references ?? [];

  return (
    <Sheet open={id != null} onOpenChange={(open) => !open && onClose()}>
      <SheetContent className="grid h-full w-full! max-w-none! grid-rows-[auto_minmax(0,1fr)_auto] gap-0 overflow-hidden bg-background p-0 text-foreground sm:w-[36rem]! sm:max-w-[36rem]!">
        <SheetHeader className="border-b bg-background px-5 py-4 pr-12">
          <SheetTitle className="text-base leading-snug">{entry?.title || "条目详情"}</SheetTitle>
          {entry ? (
            <>
              <div className="flex flex-wrap items-center gap-1.5 pt-1">
                <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-muted-foreground text-xs">
                  {entry.external_id || entry.nkey}
                </code>
                <StatusBadge domain="severity" value={entry.severity} dot />
                <Badge variant="outline">{KIND_LABEL[entry.kind] || entry.kind}</Badge>
                {entry.actively_exploited && <Badge variant="destructive">在野利用</Badge>}
                {entry.has_poc && <Badge variant="secondary">含 PoC</Badge>}
              </div>
              <SheetDescription className="pt-1 text-xs leading-relaxed">{CLUE}</SheetDescription>
            </>
          ) : (
            <SheetDescription>加载中…</SheetDescription>
          )}
        </SheetHeader>
        <div className="min-h-0 overflow-y-auto px-5 py-4">
          {!entry || !detail ? (
            <p className="text-muted-foreground text-sm">加载中…</p>
          ) : (
            <div className="space-y-4">
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm">摘要</CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="text-sm leading-relaxed whitespace-pre-wrap">{entry.summary || "（无摘要）"}</p>
                </CardContent>
              </Card>
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm">属性</CardTitle>
                </CardHeader>
                <CardContent className="divide-y pt-0">
                  <MetaRow label="CVSS">
                    <span className="tabular-nums">{entry.cvss_score ?? "—"}</span>
                  </MetaRow>
                  <MetaRow label="来源">
                    <span>{sources.length > 0 ? sources.map(sourceLabel).join(" · ") : "—"}</span>
                  </MetaRow>
                  <MetaRow label="产品">
                    {products.length > 0 ? (
                      <div className="flex flex-wrap justify-end gap-1">
                        {products.map((product) => (
                          <code key={product} className="max-w-56 truncate rounded bg-muted px-1.5 py-0.5 font-mono text-xs" title={product}>
                            {product}
                          </code>
                        ))}
                      </div>
                    ) : (
                      <span className="text-muted-foreground">—</span>
                    )}
                  </MetaRow>
                  <MetaRow label="受影响版本">
                    <span className="whitespace-pre-wrap">{entry.affected_versions || "—"}</span>
                  </MetaRow>
                </CardContent>
              </Card>
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm">检测思路</CardTitle>
                </CardHeader>
                <CardContent>
                  {entry.detection_guide ? (
                    <pre className="max-h-64 overflow-auto rounded-md bg-muted px-3 py-2 font-mono text-xs whitespace-pre-wrap">
                      {entry.detection_guide}
                    </pre>
                  ) : (
                    <p className="text-muted-foreground text-sm">（空）</p>
                  )}
                </CardContent>
              </Card>
              {entry.remediation && (
                <Card>
                  <CardHeader>
                    <CardTitle className="text-sm">修复建议</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <pre className="max-h-48 overflow-auto rounded-md bg-muted px-3 py-2 font-mono text-xs whitespace-pre-wrap">
                      {entry.remediation}
                    </pre>
                  </CardContent>
                </Card>
              )}
              {entry.poc_snippet && (
                <Card>
                  <CardHeader>
                    <CardTitle className="text-sm">PoC 片段</CardTitle>
                    <CardAction>
                      <CopyButton text={entry.poc_snippet} />
                    </CardAction>
                  </CardHeader>
                  <CardContent>
                    <pre className="max-h-64 overflow-auto rounded-md bg-muted px-3 py-2 font-mono text-xs whitespace-pre-wrap">
                      {entry.poc_snippet}
                    </pre>
                  </CardContent>
                </Card>
              )}
              {references.length > 0 && (
                <Card>
                  <CardHeader>
                    <CardTitle className="text-sm">参考</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-1">
                    {references.map((ref) => (
                      <a
                        key={ref.url}
                        href={ref.url}
                        target="_blank"
                        rel="noreferrer"
                        className="block truncate text-primary text-sm hover:underline"
                      >
                        {ref.title || ref.url}
                      </a>
                    ))}
                  </CardContent>
                </Card>
              )}
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm">命中存量资产 ({assets.length})</CardTitle>
                </CardHeader>
                <CardContent className="space-y-2">
                  {assets.map((asset) => (
                    <label key={asset.asset_id} className="flex items-start gap-3 rounded-lg border px-3 py-2 hover:bg-muted/50">
                      <Checkbox
                        className="mt-0.5"
                        checked={picked.includes(asset.asset_id)}
                        onCheckedChange={(checked) =>
                          setPicked((cur) =>
                            checked === true
                              ? cur.includes(asset.asset_id)
                                ? cur
                                : [...cur, asset.asset_id]
                              : cur.filter((x) => x !== asset.asset_id),
                          )
                        }
                      />
                      <span className="min-w-0">
                        <span className="block text-sm">{asset.label}</span>
                        {(asset.matched_tech ?? []).length > 0 && (
                          <span className="text-muted-foreground text-xs">{(asset.matched_tech ?? []).join(", ")}</span>
                        )}
                      </span>
                    </label>
                  ))}
                  {assets.length === 0 && <p className="text-muted-foreground text-sm">没有命中资产</p>}
                </CardContent>
              </Card>
              {findings.length > 0 && (
                <Card>
                  <CardHeader>
                    <CardTitle className="text-sm">关联历史漏洞发现</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-2">
                    {findings.map((f) => (
                      <Link
                        key={f.id}
                        href={`/function/findings/detail?id=${f.id}`}
                        className="flex items-center justify-between gap-2 rounded-lg border px-3 py-2 text-sm hover:bg-muted"
                      >
                        <span className="min-w-0 truncate font-medium">{f.name || f.vulnclass}</span>
                        <StatusBadge domain="severity" value={f.severity} />
                      </Link>
                    ))}
                  </CardContent>
                </Card>
              )}
            </div>
          )}
        </div>
        {entry && (
          <SheetFooter className="mt-0 border-t bg-background px-5 py-3 sm:flex-row sm:justify-end">
            <Button variant="outline" onClick={() => setEdit(true)}>
              编辑
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
          </SheetFooter>
        )}
        {entry && (
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
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>保存后正文锁定，后续同步只补充编号、在野利用和来源。</DialogDescription>
        </DialogHeader>
        <FieldGroup>
          <Field>
            <FieldLabel htmlFor="kb-entry-title">标题</FieldLabel>
            <Input id="kb-entry-title" value={titleText} onChange={(e) => setTitleText(e.target.value)} />
          </Field>
          <Field>
            <FieldLabel htmlFor="kb-entry-summary">摘要</FieldLabel>
            <Textarea id="kb-entry-summary" value={summary} onChange={(e) => setSummary(e.target.value)} />
          </Field>
          <Field>
            <FieldLabel htmlFor="kb-entry-guide">检测思路</FieldLabel>
            <Textarea id="kb-entry-guide" value={guide} onChange={(e) => setGuide(e.target.value)} />
          </Field>
          <Field>
            <FieldLabel htmlFor="kb-entry-products">产品（逗号分隔）</FieldLabel>
            <Input id="kb-entry-products" value={products} onChange={(e) => setProducts(e.target.value)} />
          </Field>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field>
              <FieldLabel>类型</FieldLabel>
              <Select value={kind} onValueChange={setKind}>
                <SelectTrigger className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="methodology">方法</SelectItem>
                  <SelectItem value="checklist">清单</SelectItem>
                  <SelectItem value="poc">PoC</SelectItem>
                  <SelectItem value="cve">漏洞</SelectItem>
                </SelectContent>
              </Select>
            </Field>
            <Field>
              <FieldLabel>等级</FieldLabel>
              <Select value={severity} onValueChange={setSeverity}>
                <SelectTrigger className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="info">提示</SelectItem>
                  <SelectItem value="low">低危</SelectItem>
                  <SelectItem value="medium">中危</SelectItem>
                  <SelectItem value="high">高危</SelectItem>
                  <SelectItem value="critical">严重</SelectItem>
                </SelectContent>
              </Select>
            </Field>
          </div>
        </FieldGroup>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            取消
          </Button>
          <Button
            onClick={() =>
              onSubmit({
                title: titleText,
                summary,
                detection_guide: guide,
                severity,
                kind,
                products: products
                  .split(",")
                  .map((s) => s.trim())
                  .filter(Boolean),
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

const REPORT_EXTS = [".pdf", ".docx", ".html", ".htm", ".md", ".markdown", ".txt", ".json"];
const REPORT_UPLOAD_LIMIT = 20 * 1024 * 1024;

type ReportDraft = {
  id: string;
  selected: boolean;
  open: boolean;
  entry: KBEntry;
  productsText: string;
};

function reportKindLabel(kind: string) {
  if (kind === "poc") return "PoC";
  if (kind === "checklist") return "检查清单";
  if (kind === "cve") return "漏洞";
  return "方法论";
}

function splitProducts(value: string) {
  return value
    .split(/[,，]/)
    .map((s) => s.trim())
    .filter(Boolean);
}

function acceptReportFiles(list: FileList | File[] | null): File[] {
  if (!list) return [];
  return Array.from(list).filter((file) => REPORT_EXTS.some((ext) => file.name.toLowerCase().endsWith(ext)));
}

function draftsFrom(entries: KBReportParseResp["entries"]): ReportDraft[] {
  return (entries ?? []).map((entry, index) => ({
    id: `${entry.nkey || "draft"}-${index}`,
    selected: true,
    open: false,
    entry: {
      ...entry,
      products: entry.products ?? [],
      severity: entry.severity || "info",
      kind: entry.kind || "methodology",
      origin: entry.origin || "manual",
      distilled: entry.distilled ?? true,
      enabled: entry.enabled ?? true,
    },
    productsText: (entry.products ?? []).join(", "),
  }));
}

function ImportDialog({ open, onClose, onDone }: { open: boolean; onClose: () => void; onDone: () => void }) {
  const [mode, setMode] = React.useState("upload");
  const [markdown, setMarkdown] = React.useState("");
  const [jsonText, setJsonText] = React.useState("");
  const [useLLM, setUseLLM] = React.useState(true);
  const [files, setFiles] = React.useState<File[]>([]);
  const [dragOver, setDragOver] = React.useState(false);
  const [parsing, setParsing] = React.useState(false);
  const [importing, setImporting] = React.useState(false);
  const [parsed, setParsed] = React.useState(false);
  const [parsedNames, setParsedNames] = React.useState("");
  const [drafts, setDrafts] = React.useState<ReportDraft[]>([]);
  const fileRef = React.useRef<HTMLInputElement>(null);

  React.useEffect(() => {
    if (open) return;
    setMarkdown("");
    setJsonText("");
    setFiles([]);
    setParsing(false);
    setImporting(false);
    setParsed(false);
    setParsedNames("");
    setDrafts([]);
    setDragOver(false);
  }, [open]);

  const selectedCount = drafts.filter((d) => d.selected).length;

  const addFiles = (list: FileList | null) => {
    const picked = Array.from(list ?? []);
    const accepted = acceptReportFiles(picked);
    if (picked.length > 0 && accepted.length === 0) {
      toast.error("仅支持 pdf、docx、html、md、txt、json");
      return;
    }
    const next = [...files, ...accepted];
    const total = next.reduce((sum, file) => sum + file.size, 0);
    if (total > REPORT_UPLOAD_LIMIT) {
      toast.error("单次上传不超过 20MB");
      return;
    }
    setFiles(next);
    setParsed(false);
    setDrafts([]);
  };

  const parseReport = async () => {
    if (files.length === 0) {
      toast.error("请先选择报告文件");
      return;
    }
    setParsing(true);
    try {
      const res = await api.parseKBReportFiles(files, useLLM);
      const next = draftsFrom(res.entries);
      setDrafts(next);
      setParsedNames((res.files_processed ?? files.map((file) => file.name)).join("、") || files.map((file) => file.name).join("、"));
      setParsed(true);
      if (next.length === 0) toast("未拆解出候选知识条目");
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setParsing(false);
    }
  };

  const importSelected = async () => {
    const selected = drafts.filter((d) => d.selected);
    if (selected.length === 0) {
      toast.error("请至少选择一条");
      return;
    }
    setImporting(true);
    try {
      const res = await api.kbImport({
        entries: selected.map((d) => ({
          ...d.entry,
          products: splitProducts(d.productsText),
          origin: d.entry.origin || "manual",
          distilled: d.entry.distilled ?? true,
          enabled: true,
        })),
      });
      toast.success(`导入 ${res.imported} 条`);
      onDone();
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setImporting(false);
    }
  };

  const importPasted = async () => {
    const pasted = mode === "json" ? jsonText : markdown;
    if (!pasted.trim()) {
      toast.error("请粘贴内容");
      return;
    }
    setImporting(true);
    try {
      const res = await api.kbImport({ format: mode === "json" ? "json" : "markdown", content: pasted });
      toast.success(`导入 ${res.imported} 条`);
      onDone();
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setImporting(false);
    }
  };

  const patchDraft = (id: string, patch: Partial<ReportDraft>) => {
    setDrafts((prev) => prev.map((d) => (d.id === id ? { ...d, ...patch } : d)));
  };

  return (
    <Dialog open={open} onOpenChange={(next) => !next && onClose()}>
      <DialogContent className="sm:max-w-3xl">
        <DialogHeader>
          <DialogTitle>导入知识</DialogTitle>
          <DialogDescription>上传渗透报告拆解为知识条目，或粘贴 Markdown / JSON。</DialogDescription>
        </DialogHeader>
        <Tabs value={mode} onValueChange={setMode}>
          <TabsList className="w-full">
            <TabsTrigger value="upload">上传报告</TabsTrigger>
            <TabsTrigger value="markdown">粘贴 Markdown</TabsTrigger>
            <TabsTrigger value="json">粘贴 JSON</TabsTrigger>
          </TabsList>
          <TabsContent value="upload" className="mt-3">
            {parsed ? (
              <div id="kb-report-preview" className="space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <p className="text-sm">
                    已从《{parsedNames}》中拆解出 {drafts.length} 条候选知识条目（已选 {selectedCount} 条）
                  </p>
                  <div className="flex gap-2">
                    <Button type="button" size="sm" variant="outline" onClick={() => setDrafts((prev) => prev.map((d) => ({ ...d, selected: true })))}>
                      全选
                    </Button>
                    <Button type="button" size="sm" variant="outline" onClick={() => setDrafts((prev) => prev.map((d) => ({ ...d, selected: false })))}>
                      取消全选
                    </Button>
                    <Button
                      type="button"
                      size="sm"
                      variant="outline"
                      onClick={() => {
                        setParsed(false);
                        setDrafts([]);
                        setFiles([]);
                        setParsedNames("");
                      }}
                    >
                      重新上传
                    </Button>
                  </div>
                </div>
                {drafts.length === 0 ? (
                  <p className="rounded-lg border bg-muted/30 px-3 py-6 text-center text-sm text-muted-foreground">没有可导入的条目</p>
                ) : (
                  <div className="space-y-2">
                    {drafts.map((draft) => (
                      <ReportDraftCard
                        key={draft.id}
                        draft={draft}
                        onToggle={(selected) => patchDraft(draft.id, { selected })}
                        onOpen={() => patchDraft(draft.id, { open: !draft.open })}
                        onEntry={(patch) => patchDraft(draft.id, { entry: { ...draft.entry, ...patch } })}
                        onProducts={(productsText) => patchDraft(draft.id, { productsText })}
                      />
                    ))}
                  </div>
                )}
              </div>
            ) : (
              <div className="space-y-3">
                <button
                  type="button"
                  onClick={() => fileRef.current?.click()}
                  onDragOver={(e) => {
                    e.preventDefault();
                    setDragOver(true);
                  }}
                  onDragLeave={() => setDragOver(false)}
                  onDrop={(e) => {
                    e.preventDefault();
                    setDragOver(false);
                    addFiles(e.dataTransfer.files);
                  }}
                  className={cn(
                    "flex min-h-28 w-full flex-col items-center justify-center gap-2 rounded-lg border border-dashed px-4 py-6 text-sm",
                    dragOver ? "border-primary bg-muted" : "border-border bg-muted/30",
                  )}
                >
                  <UploadIcon className="size-4 text-muted-foreground" />
                  <span>拖入或点击选择 .pdf / .docx / .html / .md / .txt / .json，可一次选择多个文件</span>
                </button>
                <input
                  id="kb-report-file"
                  ref={fileRef}
                  type="file"
                  multiple
                  accept={REPORT_EXTS.join(",")}
                  className="hidden"
                  onChange={(e) => {
                    addFiles(e.target.files);
                    e.target.value = "";
                  }}
                />
                {files.length > 0 && (
                  <ul className="space-y-1 text-sm text-muted-foreground">
                    {files.map((file) => (
                      <li key={`${file.name}-${file.size}-${file.lastModified}`}>{file.name}</li>
                    ))}
                  </ul>
                )}
                <div className="flex items-center justify-between gap-3 rounded-lg border bg-muted/30 px-3 py-2">
                  <label htmlFor="kb-report-use-llm" className="text-sm">
                    启用 AI 自动拆解漏洞与方法论（自动脱敏客户域名/IP/凭据）
                  </label>
                  <Switch id="kb-report-use-llm" checked={useLLM} onCheckedChange={setUseLLM} />
                </div>
                {parsing && <p className="text-sm text-muted-foreground">正在提取文档结构并由 AI 脱敏拆解知识条目...</p>}
              </div>
            )}
          </TabsContent>
          <TabsContent value="markdown" className="mt-3">
            <Field>
              <FieldLabel htmlFor="kb-import-content">Markdown 按一级标题拆成方法条目</FieldLabel>
              <Textarea id="kb-import-content" value={markdown} onChange={(e) => setMarkdown(e.target.value)} className="min-h-40" />
            </Field>
          </TabsContent>
          <TabsContent value="json" className="mt-3">
            <Field>
              <FieldLabel htmlFor="kb-import-json">JSON 按条目数组写入</FieldLabel>
              <Textarea id="kb-import-json" value={jsonText} onChange={(e) => setJsonText(e.target.value)} className="min-h-40 font-mono" />
            </Field>
          </TabsContent>
        </Tabs>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            取消
          </Button>
          {mode === "upload" && parsed ? (
            <Button id="kb-report-confirm" disabled={importing || selectedCount === 0} onClick={() => void importSelected()}>
              确认导入选中条目 ({selectedCount})
            </Button>
          ) : mode === "upload" ? (
            <Button id="kb-report-parse" disabled={parsing || files.length === 0} onClick={() => void parseReport()}>
              {parsing ? "正在提取文档结构并由 AI 脱敏拆解知识条目..." : "解析并拆解报告"}
            </Button>
          ) : (
            <Button disabled={importing} onClick={() => void importPasted()}>
              导入
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function ReportDraftCard({
  draft,
  onToggle,
  onOpen,
  onEntry,
  onProducts,
}: {
  draft: ReportDraft;
  onToggle: (selected: boolean) => void;
  onOpen: () => void;
  onEntry: (patch: Partial<KBEntry>) => void;
  onProducts: (value: string) => void;
}) {
  const products = splitProducts(draft.productsText);
  return (
    <div data-testid="kb-report-card" className="rounded-lg border bg-muted/30 p-3">
      <div className="flex items-start gap-2">
        <Checkbox checked={draft.selected} onCheckedChange={(value) => onToggle(value === true)} aria-label={`选择 ${draft.entry.title}`} />
        {draft.entry.severity && draft.entry.severity !== "info" ? (
          <StatusBadge domain="severity" value={draft.entry.severity} />
        ) : (
          <Badge variant="outline">信息</Badge>
        )}
        <span className="text-xs text-muted-foreground">{reportKindLabel(draft.entry.kind)}</span>
        <div className="min-w-0 flex-1">
          <div className="font-medium">{draft.entry.title}</div>
          {products.length > 0 && (
            <div className="mt-1 flex flex-wrap gap-1">
              {products.map((product) => (
                <Badge key={product} variant="secondary">
                  {product}
                </Badge>
              ))}
            </div>
          )}
          {draft.entry.summary && <p className="mt-1 line-clamp-2 text-sm text-muted-foreground">{draft.entry.summary}</p>}
        </div>
        <Button type="button" size="sm" variant="ghost" onClick={onOpen}>
          {draft.open ? "收起" : "展开编辑"}
        </Button>
      </div>
      {draft.open && (
        <div className="mt-3 grid gap-3">
          <Field>
            <FieldLabel>标题</FieldLabel>
            <Input value={draft.entry.title} onChange={(e) => onEntry({ title: e.target.value })} />
          </Field>
          <div className="grid gap-3 sm:grid-cols-2">
            <Field>
              <FieldLabel>类型</FieldLabel>
              <Select value={draft.entry.kind || "methodology"} onValueChange={(kind) => onEntry({ kind })}>
                <SelectTrigger className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectGroup>
                    <SelectItem value="poc">PoC</SelectItem>
                    <SelectItem value="methodology">方法论</SelectItem>
                    <SelectItem value="checklist">检查清单</SelectItem>
                    <SelectItem value="cve">漏洞</SelectItem>
                  </SelectGroup>
                </SelectContent>
              </Select>
            </Field>
            <Field>
              <FieldLabel>等级</FieldLabel>
              <Select value={draft.entry.severity || "info"} onValueChange={(severity) => onEntry({ severity })}>
                <SelectTrigger className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectGroup>
                    <SelectItem value="info">提示</SelectItem>
                    <SelectItem value="low">低危</SelectItem>
                    <SelectItem value="medium">中危</SelectItem>
                    <SelectItem value="high">高危</SelectItem>
                    <SelectItem value="critical">严重</SelectItem>
                  </SelectGroup>
                </SelectContent>
              </Select>
            </Field>
          </div>
          <Field>
            <FieldLabel>产品（逗号分隔）</FieldLabel>
            <Input value={draft.productsText} onChange={(e) => onProducts(e.target.value)} />
          </Field>
          <Field>
            <FieldLabel>检测思路</FieldLabel>
            <Textarea value={draft.entry.detection_guide ?? ""} onChange={(e) => onEntry({ detection_guide: e.target.value })} className="min-h-24" />
          </Field>
          <Field>
            <FieldLabel>PoC</FieldLabel>
            <Textarea value={draft.entry.poc_snippet ?? ""} onChange={(e) => onEntry({ poc_snippet: e.target.value })} className="min-h-24 font-mono" />
          </Field>
          <Field>
            <FieldLabel>修复建议</FieldLabel>
            <Textarea value={draft.entry.remediation ?? ""} onChange={(e) => onEntry({ remediation: e.target.value })} className="min-h-20" />
          </Field>
        </div>
      )}
    </div>
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
      <Card className="gap-0 overflow-hidden py-0">
        <CardHeader className="border-b py-4">
          <CardTitle className="text-base">情报源</CardTitle>
          <CardDescription>启用后按周期同步。内置源不能删除。</CardDescription>
          <CardAction>
            <Button size="sm" variant="outline" onClick={() => setCreateOpen(true)}>
              添加自定义源
            </Button>
          </CardAction>
        </CardHeader>
        <CardContent className="divide-y px-0">
          {sources.map((src) => (
            <SourceCard key={src.id} src={src} onChanged={load} />
          ))}
          {sources.length === 0 && <p className="px-4 py-8 text-center text-muted-foreground text-sm">没有情报源</p>}
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
      <Card className="gap-0 overflow-hidden py-0">
        <CardHeader className="border-b py-4">
          <CardTitle className="text-base">同步日志</CardTitle>
        </CardHeader>
        <CardContent className="px-0">
          <Table className="table-fixed">
            <TableHeader>
              <TableRow>
                <TableHead className="w-[18%]">源</TableHead>
                <TableHead>状态</TableHead>
                <TableHead>拉取 / 新增 / 合并</TableHead>
                <TableHead>耗时</TableHead>
                <TableHead>错误</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {runs.map((run) => (
                <TableRow key={run.id}>
                  <TableCell className="overflow-hidden font-medium">
                    <span className="block truncate" title={run.source_key}>
                      {sourceLabel(run.source_key || String(run.source_id))}
                    </span>
                  </TableCell>
                  <TableCell>
                    <SyncStatusBadge status={run.status} />
                  </TableCell>
                  <TableCell className="tabular-nums">
                    {run.fetched_count} / {run.upserted_count} / {run.merged_count}
                  </TableCell>
                  <TableCell className="text-xs tabular-nums">{runDuration(run)}</TableCell>
                  <TableCell className="overflow-hidden text-destructive text-xs" title={run.error}>
                    <span className="block truncate">{run.error || "—"}</span>
                  </TableCell>
                </TableRow>
              ))}
              {runs.length === 0 && (
                <TableRow>
                  <TableCell colSpan={5} className="py-10 text-center text-muted-foreground">
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
    <div className="px-4 py-3">
      <div className="flex flex-wrap items-center gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-medium">{src.name}</span>
            <Badge variant="outline">{SOURCE_KIND[src.kind] || src.kind}</Badge>
            <SyncStatusBadge status={src.last_status} />
            {src.builtin && <Badge variant="secondary">内置</Badge>}
          </div>
          <p className="mt-1 truncate text-muted-foreground text-xs" title={src.last_error || undefined}>
            <span className="tabular-nums">{src.entry_count} 条</span>
            {src.last_error ? <span className="text-destructive"> · {src.last_error}</span> : null}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Switch
            checked={src.enabled}
            aria-label={`启用 ${src.name}`}
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
            {open ? "收起" : "配置"}
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
        <FieldGroup className="mt-4 border-t pt-4">
          <div className="grid gap-4 sm:grid-cols-2">
            <Field>
              <FieldLabel htmlFor={`kb-hours-${src.id}`}>同步周期（小时）</FieldLabel>
              <Input id={`kb-hours-${src.id}`} value={hours} onChange={(e) => setHours(e.target.value)} />
            </Field>
            {windowed && (
              <>
                <Field>
                  <FieldLabel>最低等级</FieldLabel>
                  <Select value={minSev} onValueChange={setMinSev}>
                    <SelectTrigger className="w-full">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="critical">严重</SelectItem>
                      <SelectItem value="high">高危</SelectItem>
                      <SelectItem value="medium">中危</SelectItem>
                      <SelectItem value="low">低危</SelectItem>
                    </SelectContent>
                  </Select>
                </Field>
                <Field>
                  <FieldLabel htmlFor={`kb-days-${src.id}`}>时间窗口（天，最多 119）</FieldLabel>
                  <Input id={`kb-days-${src.id}`} value={sinceDays} onChange={(e) => setSinceDays(e.target.value)} />
                </Field>
              </>
            )}
            {feed && (
              <Field className="sm:col-span-2">
                <FieldLabel htmlFor={`kb-feed-${src.id}`}>Feed URL</FieldLabel>
                <Input id={`kb-feed-${src.id}`} value={feedURL} onChange={(e) => setFeedURL(e.target.value)} />
              </Field>
            )}
            {src.kind === "avd" && (
              <Field>
                <FieldLabel htmlFor={`kb-pages-${src.id}`}>列表页数</FieldLabel>
                <Input id={`kb-pages-${src.id}`} value={pageLimit} onChange={(e) => setPageLimit(e.target.value)} />
              </Field>
            )}
            {git && (
              <>
                <Field className="sm:col-span-2">
                  <FieldLabel htmlFor={`kb-repo-${src.id}`}>仓库 URL</FieldLabel>
                  <Input
                    id={`kb-repo-${src.id}`}
                    value={repoURL}
                    placeholder="https://github.com/org/repo"
                    onChange={(e) => setRepoURL(e.target.value)}
                  />
                </Field>
                <Field>
                  <FieldLabel htmlFor={`kb-branch-${src.id}`}>分支</FieldLabel>
                  <Input id={`kb-branch-${src.id}`} value={branch} onChange={(e) => setBranch(e.target.value)} />
                </Field>
                <Field>
                  <FieldLabel htmlFor={`kb-path-${src.id}`}>路径</FieldLabel>
                  <Input id={`kb-path-${src.id}`} value={repoPath} onChange={(e) => setRepoPath(e.target.value)} />
                </Field>
              </>
            )}
            {(windowed || src.kind === "nuclei") && (
              <Field className="sm:col-span-2">
                <FieldLabel htmlFor={`kb-key-${src.id}`}>API Key{src.api_key_set ? "（已设置，留空则保留）" : ""}</FieldLabel>
                <Input id={`kb-key-${src.id}`} type="password" value={apiKey} autoComplete="off" onChange={(e) => setApiKey(e.target.value)} />
              </Field>
            )}
          </div>
          <Field orientation="horizontal">
            <Switch id={`kb-distill-${src.id}`} checked={distill} onCheckedChange={setDistill} />
            <FieldLabel htmlFor={`kb-distill-${src.id}`}>同步后用模型整理空的检测思路（默认关闭）</FieldLabel>
          </Field>
          <div>
            <Button size="sm" onClick={() => void save()}>
              保存配置
            </Button>
          </div>
        </FieldGroup>
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
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>添加自定义源</DialogTitle>
          <DialogDescription>自定义源可以是 Git 仓库里的 Markdown，或一条 RSS。</DialogDescription>
        </DialogHeader>
        <FieldGroup>
          <Field>
            <FieldLabel htmlFor="kb-source-key">标识（字母、数字、下划线）</FieldLabel>
            <Input id="kb-source-key" value={key} onChange={(e) => setKey(e.target.value)} />
          </Field>
          <Field>
            <FieldLabel htmlFor="kb-source-name">名称</FieldLabel>
            <Input id="kb-source-name" value={name} onChange={(e) => setName(e.target.value)} />
          </Field>
          <Field>
            <FieldLabel>类型</FieldLabel>
            <Select value={kind} onValueChange={setKind}>
              <SelectTrigger className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="git_markdown">Git Markdown</SelectItem>
                <SelectItem value="rss">RSS</SelectItem>
              </SelectContent>
            </Select>
          </Field>
          <Field>
            <FieldLabel htmlFor="kb-source-target">{kind === "rss" ? "Feed URL" : "仓库 URL"}</FieldLabel>
            <Input id="kb-source-target" value={target} onChange={(e) => setTarget(e.target.value)} />
          </Field>
        </FieldGroup>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            取消
          </Button>
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
