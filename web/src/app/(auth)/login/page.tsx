"use client";

import { useEffect, useRef, useState } from "react";

import { useRouter } from "next/navigation";

import { AlertTriangle, ShieldCheck } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogClose, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api } from "@/lib/api";
import { auth } from "@/lib/auth";

export default function LoginPage() {
  const router = useRouter();
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [checking, setChecking] = useState(true);
  const [agreed, setAgreed] = useState(false);
  const [termsOpen, setTermsOpen] = useState(false);
  const [readToEnd, setReadToEnd] = useState(false);
  const termsBodyRef = useRef<HTMLDivElement>(null);

  // 滚动到条款底部（含无需滚动即可完整展示的情况）方可点击「同意」。
  function handleTermsScroll() {
    const el = termsBodyRef.current;
    if (!el) return;
    if (el.scrollTop + el.clientHeight >= el.scrollHeight - 8) setReadToEnd(true);
  }

  useEffect(() => {
    if (!termsOpen) return;
    // 打开时重置，并处理内容本就不足一屏、无法触发滚动的场景。
    setReadToEnd(false);
    const el = termsBodyRef.current;
    if (el && el.scrollHeight <= el.clientHeight + 8) setReadToEnd(true);
  }, [termsOpen]);

  useEffect(() => {
    // 已登录直接进主界面（静态导出下无 middleware 代劳这层跳转）。
    const token = auth.getToken();
    if (token) {
      // localStorage 可能仍有凭据但 cookie 已丢失。先同步，再发起全新请求，
      // 避免服务端守卫或路由缓存把跳转送回仍处于 checking 状态的登录页。
      auth.setToken(token);
      window.location.replace("/function/tasks");
      return;
    }
    api
      .authStatus()
      .then(({ initialized }) => {
        if (!initialized) router.replace("/setup");
      })
      .catch(() => setError("无法连接到后端服务"))
      .finally(() => setChecking(false));
  }, [router]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!agreed) {
      setError("请先阅读并确认《使用须知》");
      return;
    }
    setLoading(true);
    setError("");
    try {
      const { token } = await api.login("ARTEX", password);
      auth.setToken(token);
      window.location.replace("/function/tasks");
    } catch {
      setError("用户名或密码错误");
    } finally {
      setLoading(false);
    }
  }

  if (checking) {
    return (
      <div role="status" className="flex min-h-dvh items-center justify-center text-muted-foreground">
        正在检查登录状态…
      </div>
    );
  }

  return (
    <div className="flex h-dvh">
      {/* Left panel */}
      <div className="hidden flex-col items-center justify-center bg-primary p-12 text-center lg:flex lg:w-1/3 dark:bg-background">
        <div className="relative flex items-center justify-center">
          <div className="absolute size-80 rounded-full border border-primary-foreground/10 dark:border-muted-foreground/10" />
          <div className="absolute size-60 rounded-full border border-primary-foreground/15 dark:border-muted-foreground/15" />
          <div className="absolute size-40 rounded-full border border-primary-foreground/20 dark:border-muted-foreground/20" />
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img
            src="/logo.png"
            alt="ARTEX"
            width={160}
            height={160}
            className="relative brightness-0 invert dark:opacity-20"
          />
        </div>
      </div>

      {/* Right panel */}
      <div className="flex w-full items-center justify-center bg-background p-8 lg:w-2/3">
        <div className="w-full max-w-md space-y-10 py-24 lg:py-32">
          <div className="space-y-4 text-center">
            <h2 className="text-2xl font-medium tracking-tight">登录</h2>
            <p className="mx-auto max-w-xl text-muted-foreground">欢迎回来，请输入密码以继续使用 ARTEX</p>
          </div>
          <form onSubmit={handleSubmit} className="flex flex-col gap-4">
            <div className="space-y-1.5">
              <Label htmlFor="username">用户名</Label>
              <Input id="username" value="ARTEX" readOnly className="bg-muted text-muted-foreground" />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="password">密码</Label>
              <Input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="请输入密码"
                autoFocus
                autoComplete="current-password"
              />
            </div>
            <div className="flex items-start gap-2">
              <Checkbox
                id="agree-terms"
                checked={agreed}
                onCheckedChange={(v) => setAgreed(v === true)}
                className="mt-0.5"
              />
              <Label htmlFor="agree-terms" className="text-sm font-normal leading-relaxed text-muted-foreground">
                我已阅读并确认
                <button
                  type="button"
                  onClick={() => setTermsOpen(true)}
                  className="mx-0.5 font-medium text-primary underline-offset-4 hover:underline"
                >
                  《使用须知》
                </button>
              </Label>
            </div>
            {error && <p className="text-sm text-destructive">{error}</p>}
            <Button type="submit" className="w-full" disabled={loading || !password || !agreed}>
              {loading ? "登录中..." : "登录"}
            </Button>
          </form>
        </div>
      </div>

      <Dialog open={termsOpen} onOpenChange={setTermsOpen}>
        <DialogContent className="gap-0 p-0 sm:max-w-2xl">
          <DialogHeader className="flex-row items-center gap-3 border-b px-6 py-4">
            <div className="flex size-10 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary">
              <ShieldCheck className="size-5" />
            </div>
            <div className="space-y-0.5">
              <DialogTitle className="text-base">ARTEX-local 使用须知</DialogTitle>
              <p className="text-xs text-muted-foreground">
                版本 v1.1 · 更新日期 2026-11-12 · 请在登录前完整阅读以下内容
              </p>
            </div>
          </DialogHeader>

          <div
            ref={termsBodyRef}
            onScroll={handleTermsScroll}
            className="max-h-[60vh] space-y-5 overflow-y-auto px-6 py-5 text-sm leading-relaxed text-muted-foreground"
          >
            <p className="rounded-lg border bg-muted/40 p-3 text-foreground/80">
              本须知说明 ARTEX-local 的项目来源、授权测试边界和部署注意事项，不替代仓库内适用于具体文件的许可证，也不授予您访问或测试任何目标的权限。请在部署和使用前阅读相关项目文档。
              <span className="font-medium text-foreground">
                {" "}登录确认仅表示您已阅读本须知；每次测试仍须取得目标所有者的明确授权，并遵守约定范围。
              </span>
            </p>

            <section className="space-y-1.5">
              <h4 className="flex items-center gap-2 font-medium text-foreground">
                <span className="flex size-5 items-center justify-center rounded-md bg-muted text-xs font-semibold text-muted-foreground">
                  1
                </span>
                第一条 · 项目来源与许可证
              </h4>
              <p className="pl-7">
                本仓库是 ARTEX 的独立修改版本，由当前仓库独立维护，不代表原项目官方发布或背书。仓库根目录的 LICENSE、web/LICENSE 及各文件附带的许可声明可能不同；请依据对应文件和 NOTICE.md 核实适用条款。本须知不改变这些许可证。
              </p>
            </section>

            <section className="space-y-1.5">
              <h4 className="flex items-center gap-2 font-medium text-foreground">
                <span className="flex size-5 items-center justify-center rounded-md bg-muted text-xs font-semibold text-muted-foreground">
                  2
                </span>
                第二条 · 测试授权与范围
              </h4>
              <p className="pl-7">
                仅对您拥有或已获得目标所有者明确授权的资产开展测试。开始前应确认授权主体、目标清单、允许的测试方法、时间窗口和影响限制；授权范围外的域名、地址、账户、云服务及第三方依赖不因此获得授权。发现新的资产或系统时，应先确认其是否在范围内。
              </p>
            </section>

            <section className="space-y-2">
              <h4 className="flex items-center gap-2 font-medium text-destructive">
                <span className="flex size-5 items-center justify-center rounded-md bg-destructive/10 text-xs font-semibold text-destructive">
                  3
                </span>
                <AlertTriangle className="size-4" />
                第三条 · 操作影响与限制
              </h4>
              <ul className="ml-7 list-decimal space-y-1.5 rounded-lg border border-destructive/20 bg-destructive/5 p-3 pl-8 text-foreground/80 marker:text-destructive/70">
                <li>
                  扫描、浏览器操作和命令可能产生网络流量、改变目标状态、触发告警或影响服务可用性；应先确认测试窗口、速率和停止条件；
                </li>
                <li>主动扫描、利用验证及可能造成破坏或服务中断的操作，只能在明确授权且约定允许的范围内执行；</li>
                <li>系统中的审批、拦截和安全设置不能替代目标授权，也不能扩大授权范围；</li>
                <li>不得将系统用于超出授权范围的访问、数据获取、持久化、拒绝服务或其他违法活动。</li>
              </ul>
            </section>

            <section className="space-y-1.5">
              <h4 className="flex items-center gap-2 font-medium text-foreground">
                <span className="flex size-5 items-center justify-center rounded-md bg-muted text-xs font-semibold text-muted-foreground">
                  4
                </span>
                第四条 · 数据处理
              </h4>
              <p className="pl-7">
                任务、资产、发现、流量记录、日志和导出文件可能含有凭据、个人信息或其他敏感数据。默认 Docker 部署将数据保存在本机的 PostgreSQL 卷及项目数据目录；若配置外部 LLM 或 MCP 服务，发送给这些服务的提示词、工具参数和结果可能离开本机并受相应服务条款约束。请仅配置获准使用的服务，并保护凭据、日志、备份和导出文件。
              </p>
            </section>

            <section className="space-y-1.5">
              <h4 className="flex items-center gap-2 font-medium text-foreground">
                <span className="flex size-5 items-center justify-center rounded-md bg-muted text-xs font-semibold text-muted-foreground">
                  5
                </span>
                第五条 · 部署与访问控制
              </h4>
              <p className="pl-7">
                默认 Compose 配置将 Web/API 端口 8787 发布到宿主机网络，流量代理端口 8788 仅绑定本机回环地址。请将管理界面限制在可信网络，按需配置防火墙或反向代理，并妥善设置管理员密码及数据库凭据。
              </p>
            </section>

            <section className="space-y-1.5">
              <h4 className="flex items-center gap-2 font-medium text-foreground">
                <span className="flex size-5 items-center justify-center rounded-md bg-muted text-xs font-semibold text-muted-foreground">
                  6
                </span>
                第六条 · 结果核验
              </h4>
              <p className="pl-7">
                Agent、LLM、扫描器和外部工具的输出可能不完整或不准确。应核对原始证据、确认影响并按授权流程复测；不要仅凭自动化结论采取可能影响系统或业务的措施。
              </p>
            </section>

            <section className="space-y-1.5">
              <h4 className="flex items-center gap-2 font-medium text-foreground">
                <span className="flex size-5 items-center justify-center rounded-md bg-muted text-xs font-semibold text-muted-foreground">
                  7
                </span>
                第七条 · 合法合规使用
              </h4>
              <p className="pl-7">
                您应遵守适用于自身、目标系统和数据处理活动的法律法规、合同及组织政策，并确保获得必要的授权。各项权利、担保和责任以适用许可证及法律为准；本须知不构成法律意见，也不试图排除法律规定不得排除的责任。
              </p>
            </section>

            <section className="space-y-1.5">
              <h4 className="flex items-center gap-2 font-medium text-foreground">
                <span className="flex size-5 items-center justify-center rounded-md bg-muted text-xs font-semibold text-muted-foreground">
                  8
                </span>
                第八条 · 须知更新
              </h4>
              <p className="pl-7">
                本须知随项目版本更新。更新日期和内容以本仓库发布文件为准；如本须知与适用许可证不一致，以许可证条款为准。阅读并确认本须知不会替代具体任务的授权、范围确认和操作审批。
              </p>
            </section>
          </div>

          <DialogFooter className="mx-0 mb-0 flex-col items-stretch gap-2 rounded-b-xl px-6 sm:flex-row sm:items-center sm:justify-between">
            <p className="text-xs text-muted-foreground">
              {readToEnd ? "您已浏览全部条款" : "请将条款滚动至底部后再确认"}
            </p>
            <DialogClose asChild>
              <Button
                type="button"
                disabled={!readToEnd}
                onClick={() => {
                  setAgreed(true);
                  setError("");
                }}
              >
                我已阅读并确认使用须知
              </Button>
            </DialogClose>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
