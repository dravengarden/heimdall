import {
  createContext,
  createElement,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

export type Locale = "en" | "zh-CN";

type Catalog = Record<string, string>;

const en: Catalog = {
  "app.title": "Heimdall",
  "app.live": "live",
  "app.connecting": "connecting",
  "app.reconnecting": "reconnecting",

  "filter.placeholder": "filter by host / pod / IP / connection…  (press /)",
  "filter.allConnections": "all connections",
  "filter.all": "all",
  "filter.hideErrors": "Hide flows with errors",
  "filter.pause": "Pause live updates",
  "filter.resume": "Resume live updates",
  "filter.refetch": "Refetch",
  "filter.export": "Download visible flows as JSON",
  "filter.filtersLabel": "filters",
  "filter.clearAll": "clear all",

  "table.empty.title": "no flows match the current filter",
  "table.empty.hint": "triggered traffic from a pod will appear here automatically",
  "table.cols.id": "id",
  "table.cols.time": "time",
  "table.cols.pod": "pod",
  "table.cols.conn": "conn",
  "table.cols.dst": "dst",
  "table.cols.port": "port",
  "table.cols.up": "↑",
  "table.cols.down": "↓",
  "table.cols.dur": "dur",
  "table.cols.via": "via",

  "detail.tabs.overview": "Overview",
  "detail.tabs.raw": "Raw JSON",
  "detail.copyJson": "Copy flow as JSON",
  "detail.replay": "Replay",
  "detail.replay.todo": "Replay needs Phase B (uprobe captures); not available yet.",
  "detail.section.identity": "Identity",
  "detail.section.dst": "Destination",
  "detail.section.traffic": "Traffic",
  "detail.section.timing": "Timing",
  "detail.section.internals": "Internals",
  "detail.copy": "Copy {0}",

  "settings.title": "Settings",
  "settings.appearance": "Appearance",
  "settings.theme": "Theme",
  "settings.theme.light": "Light",
  "settings.theme.dark": "Dark",
  "settings.theme.auto": "Auto",
  "settings.fontSize": "Font size",
  "settings.language": "Language",
  "settings.language.en": "English",
  "settings.language.zh-CN": "简体中文",
  "settings.about": "About",

  "ws.open": "Live updates connected",
  "ws.connecting": "Connecting to daemon…",
  "ws.reconnecting": "Reconnecting to daemon…",

  "toast.copied": "copied {0}",
  "toast.copyFailed": "failed to copy {0}",
};

const zhCN: Catalog = {
  "app.title": "Heimdall",
  "app.live": "实时",
  "app.connecting": "连接中",
  "app.reconnecting": "重连中",

  "filter.placeholder": "搜索 hostname / pod / IP / connection…  (按 / 聚焦)",
  "filter.allConnections": "全部 connection",
  "filter.all": "全部",
  "filter.hideErrors": "隐藏出错的流量",
  "filter.pause": "暂停实时更新",
  "filter.resume": "恢复实时更新",
  "filter.refetch": "重新拉取",
  "filter.export": "把当前可见流量导出为 JSON",
  "filter.filtersLabel": "筛选",
  "filter.clearAll": "全部清除",

  "table.empty.title": "当前筛选条件下没有匹配的流量",
  "table.empty.hint": "pod 触发流量后会自动显示在这里",
  "table.cols.id": "id",
  "table.cols.time": "时间",
  "table.cols.pod": "pod",
  "table.cols.conn": "连接",
  "table.cols.dst": "目标",
  "table.cols.port": "端口",
  "table.cols.up": "↑",
  "table.cols.down": "↓",
  "table.cols.dur": "耗时",
  "table.cols.via": "经由",

  "detail.tabs.overview": "概览",
  "detail.tabs.raw": "原始 JSON",
  "detail.copyJson": "复制为 JSON",
  "detail.replay": "重放",
  "detail.replay.todo": "重放功能依赖 Phase B(uprobe 抓明文),尚未实现。",
  "detail.section.identity": "身份",
  "detail.section.dst": "目标",
  "detail.section.traffic": "流量",
  "detail.section.timing": "时间",
  "detail.section.internals": "内部",
  "detail.copy": "复制 {0}",

  "settings.title": "设置",
  "settings.appearance": "外观",
  "settings.theme": "主题",
  "settings.theme.light": "浅色",
  "settings.theme.dark": "深色",
  "settings.theme.auto": "跟随系统",
  "settings.fontSize": "字号",
  "settings.language": "语言",
  "settings.language.en": "English",
  "settings.language.zh-CN": "简体中文",
  "settings.about": "关于",

  "ws.open": "实时连接已建立",
  "ws.connecting": "正在连接 daemon…",
  "ws.reconnecting": "正在重连…",

  "toast.copied": "已复制 {0}",
  "toast.copyFailed": "复制 {0} 失败",
};

const catalogs: Record<Locale, Catalog> = { en, "zh-CN": zhCN };

const STORAGE_KEY = "heimdall.locale";

function detectLocale(): Locale {
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    if (v === "en" || v === "zh-CN") return v;
  } catch {
    /* ignore */
  }
  const nav = (navigator.language || "en").toLowerCase();
  if (nav.startsWith("zh")) return "zh-CN";
  return "en";
}

interface I18nValue {
  locale: Locale;
  setLocale: (l: Locale) => void;
  t: (key: string, ...args: ReadonlyArray<string | number>) => string;
}

const I18nContext = createContext<I18nValue | null>(null);

interface ProviderProps {
  children: ReactNode;
}

export function I18nProvider({ children }: ProviderProps) {
  const [locale, setLocaleState] = useState<Locale>(detectLocale);

  const setLocale = (l: Locale): void => {
    setLocaleState(l);
    try {
      localStorage.setItem(STORAGE_KEY, l);
    } catch {
      /* ignore */
    }
  };

  useEffect(() => {
    document.documentElement.lang = locale;
  }, [locale]);

  const value = useMemo<I18nValue>(() => {
    const cat = catalogs[locale];
    return {
      locale,
      setLocale,
      t: (key, ...args) => format(cat[key] ?? key, args),
    };
  }, [locale]);

  return createElement(I18nContext.Provider, { value }, children);
}

export function useI18n(): I18nValue {
  const v = useContext(I18nContext);
  if (!v) throw new Error("I18nProvider missing");
  return v;
}

function format(template: string, args: ReadonlyArray<string | number>): string {
  return template.replace(/\{(\d+)\}/g, (_, idx: string) => {
    const i = Number(idx);
    return String(args[i] ?? `{${idx}}`);
  });
}
