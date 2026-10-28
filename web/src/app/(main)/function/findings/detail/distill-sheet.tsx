"use client";

import * as React from "react";

import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { FindingDistillDraft, FindingDistillPreview, FindingKBEntry } from "@/lib/types";

const KINDS = [
  { value: "poc", label: "PoC 规则" },
  { value: "methodology", label: "实战方法论" },
  { value: "checklist", label: "检查清单" },
];

const SEVERITIES = [
  { value: "critical", label: "严重" },
  { value: "high", label: "高" },
  { value: "medium", label: "中" },
  { value: "low", label: "低" },
  { value: "info", label: "提示" },
];

function splitProducts(text: string) {
  return text
    .split(/[,，]/)
    .map((item) => item.trim())
    .filter(Boolean);
}

export function FindingDistillSheet({
  findingId,
  open,
  onOpenChange,
  onSaved,
}: {
  findingId: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSaved: () => void;
}) {
  const [loading, setLoading] = React.useState(false);
  const [saving, setSaving] = React.useState(false);
  const [notes, setNotes] = React.useState("");
  const [preview, setPreview] = React.useState<FindingDistillPreview | null>(null);
  const [draft, setDraft] = React.useState<FindingDistillDraft | null>(null);
  const [products, setProducts] = React.useState("");
  const [mode, setMode] = React.useState<"enrich_existing" | "new_entry">("new_entry");
  const [target, setTarget] = React.useState(0);

  const applyPreview = React.useCallback((next: FindingDistillPreview) => {
    const linked = next.linked_kb_entries ?? [];
    setPreview(next);
    setDraft(next.draft);
    setProducts((next.draft.products ?? []).join(", "));
    setMode(next.suggested_mode === "enrich_existing" && linked.length > 0 ? "enrich_existing" : "new_entry");
    const preferred = next.target_kb_id && next.target_kb_id > 0 ? next.target_kb_id : linked[0]?.id ?? 0;
    setTarget(preferred);
  }, []);

  const loadPreview = React.useCallback(
    async (extra: string, targetID: number) => {
      setLoading(true);
      try {
        const next = await api.distillFindingPreview(findingId, {
          extra_notes: extra.trim() || undefined,
          target_kb_id: targetID > 0 ? targetID : undefined,
        });
        applyPreview(next);
      } catch (e) {
        toast.error("提炼失败：" + (e as Error).message);
      } finally {
        setLoading(false);
      }
    },
    [applyPreview, findingId],
  );

  React.useEffect(() => {
    if (!open) return;
    setNotes("");
    void loadPreview("", 0);
  }, [open, findingId, loadPreview]);

  const linked = preview?.linked_kb_entries ?? [];
  const trafficCount = preview?.redacted_traffic_count ?? 0;

  const patch = (part: Partial<FindingDistillDraft>) => {
    setDraft((cur) => (cur ? { ...cur, ...part } : cur));
  };

  const save = async () => {
    if (!draft) return;
    setSaving(true);
    try {
      const res = await api.distillFindingKB(findingId, {
        mode,
        target_kb_id: mode === "enrich_existing" ? target : undefined,
        draft: { ...draft, products: splitProducts(products), suggested_mode: mode },
      });
      toast.success(`已入库：${res.entry.title || "知识条目"}`);
      onOpenChange(false);
      onSaved();
    } catch (e) {
      toast.error("入库失败：" + (e as Error).message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent className="grid h-full w-full! max-w-none! grid-rows-[auto_minmax(0,1fr)_auto] gap-0 overflow-hidden bg-background p-0 text-foreground sm:w-[36rem]! sm:max-w-[36rem]!">
        <SheetHeader className="border-b bg-background px-5 py-4 pr-12">
          <SheetTitle className="text-base">沉淀实战经验至知识库</SheetTitle>
          <SheetDescription className="text-xs leading-relaxed">
            {trafficCount > 0
              ? `已自动从 ${trafficCount} 条关联 HTTP 流量与资产指纹中提取并擦除敏感 Host/IP/凭据`
              : "已从漏洞证据与资产指纹中整理检测线索。当前没有可复用的 HTTP 流量。"}
          </SheetDescription>
        </SheetHeader>
        <div className="min-h-0 space-y-4 overflow-y-auto px-5 py-4">
          {loading && !draft ? <p className="text-muted-foreground text-sm">正在脱敏并提炼…</p> : null}
          {draft ? (
            <>
              {linked.length > 0 ? (
                <div className="space-y-2">
                  <Label>入库方式</Label>
                  <RadioGroup value={mode} onValueChange={(value) => setMode(value as "enrich_existing" | "new_entry")}>
                    <label className="flex items-center gap-2 text-sm">
                      <RadioGroupItem value="enrich_existing" />
                      增量补充至现有知识条目（推荐）
                    </label>
                    <label className="flex items-center gap-2 text-sm">
                      <RadioGroupItem value="new_entry" />
                      另存为独立实战方法论条目
                    </label>
                  </RadioGroup>
                  {mode === "enrich_existing" ? (
                    <Select value={String(target || linked[0].id)} onValueChange={(value) => setTarget(Number(value))}>
                      <SelectTrigger>
                        <SelectValue placeholder="选择要补充的条目" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectGroup>
                          {linked.map((entry) => (
                            <SelectItem key={entry.id} value={String(entry.id)}>
                              {entryLabel(entry)}
                            </SelectItem>
                          ))}
                        </SelectGroup>
                      </SelectContent>
                    </Select>
                  ) : null}
                </div>
              ) : null}
              <Field label="条目名称">
                <Input value={draft.title} onChange={(e) => patch({ title: e.target.value })} />
              </Field>
              <div className="grid grid-cols-2 gap-3">
                <Field label="知识分类">
                  <Select value={draft.kind || "methodology"} onValueChange={(value) => patch({ kind: value })}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectGroup>
                        {KINDS.map((item) => (
                          <SelectItem key={item.value} value={item.value}>
                            {item.label}
                          </SelectItem>
                        ))}
                      </SelectGroup>
                    </SelectContent>
                  </Select>
                </Field>
                <Field label="严重等级">
                  <Select value={draft.severity || "info"} onValueChange={(value) => patch({ severity: value })}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectGroup>
                        {SEVERITIES.map((item) => (
                          <SelectItem key={item.value} value={item.value}>
                            {item.label}
                          </SelectItem>
                        ))}
                      </SelectGroup>
                    </SelectContent>
                  </Select>
                </Field>
              </div>
              <Field label="漏洞类型">
                <Input value={draft.vulnclass} onChange={(e) => patch({ vulnclass: e.target.value })} />
              </Field>
              <Field label="关联组件指纹">
                <Input value={products} onChange={(e) => setProducts(e.target.value)} placeholder="用逗号分隔" />
              </Field>
              <Field label="精炼摘要">
                <Textarea value={draft.summary} onChange={(e) => patch({ summary: e.target.value })} rows={3} />
              </Field>
              <Field label="探测与绕过指引">
                <Textarea value={draft.detection_guide} onChange={(e) => patch({ detection_guide: e.target.value })} rows={6} />
              </Field>
              <Field label="脱敏验证报文">
                <Textarea value={draft.poc_snippet} onChange={(e) => patch({ poc_snippet: e.target.value })} rows={6} className="font-mono text-xs" />
              </Field>
              <Field label="修复建议">
                <Textarea value={draft.remediation} onChange={(e) => patch({ remediation: e.target.value })} rows={3} />
              </Field>
              <Field label="补充说明">
                <Textarea
                  value={notes}
                  onChange={(e) => setNotes(e.target.value)}
                  rows={3}
                  placeholder="绕过方式、关键技巧或修复说明。重新提炼时会带上。"
                />
              </Field>
            </>
          ) : null}
        </div>
        <SheetFooter className="mt-0 border-t bg-background px-5 py-3 sm:flex-row sm:justify-end">
          <Button variant="outline" disabled={loading || saving || !findingId} onClick={() => void loadPreview(notes, target)}>
            {loading ? "提炼中…" : "重新 AI 提炼"}
          </Button>
          <Button disabled={loading || saving || !draft} onClick={() => void save()}>
            {saving ? "入库中…" : "确认入库"}
          </Button>
        </SheetFooter>
      </SheetContent>
    </Sheet>
  );
}

function entryLabel(entry: FindingKBEntry) {
  return entry.external_id ? `${entry.external_id} ${entry.title}` : entry.title;
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid gap-1.5">
      <Label className="text-muted-foreground text-xs">{label}</Label>
      {children}
    </div>
  );
}
