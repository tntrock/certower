import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { zhCN } from "./locales/zh-CN";
import { zhTW } from "./locales/zh-TW";

// Strings are written in English in the code and looked up in a dictionary
// per language; a missing translation falls back to English.
// scripts/check-i18n.mjs checks every dictionary covers every string.

export type Lang = "en" | "zh-TW" | "zh-CN";

// Each language names itself, so people can find theirs.
export const languages: { code: Lang; name: string }[] = [
  { code: "en", name: "English" },
  { code: "zh-TW", name: "繁體中文" },
  { code: "zh-CN", name: "简体中文" },
];

const dictionaries: Record<Lang, Record<string, string>> = { en: {}, "zh-TW": zhTW, "zh-CN": zhCN };

const isLang = (s: string | null): s is Lang => languages.some((l) => l.code === s);

// fromBrowser maps a BCP 47 tag to a supported language. Chinese is split
// by script: Hans (mainland, Singapore) and Hant (Taiwan, Hong Kong, Macau).
export function fromBrowser(tag: string): Lang | null {
  const t = tag.toLowerCase();
  if (!t.startsWith("zh")) return t.startsWith("en") ? "en" : null;
  if (t.includes("hant") || /-(tw|hk|mo)\b/.test(t)) return "zh-TW";
  if (t.includes("hans") || /-(cn|sg|my)\b/.test(t)) return "zh-CN";
  return "zh-CN"; // bare "zh" is most often Simplified
}

function detect(): Lang {
  try {
    const saved = localStorage.getItem("certower.lang");
    if (isLang(saved)) return saved;
  } catch {
    // storage unavailable
  }
  for (const tag of navigator.languages ?? [navigator.language]) {
    const l = fromBrowser(tag);
    if (l) return l;
  }
  return "en";
}

interface I18n {
  lang: Lang;
  setLang: (l: Lang) => void;
  t: (s: string, vars?: Record<string, string | number>) => string;
}

const Ctx = createContext<I18n | null>(null);

export function I18nProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<Lang>(detect);
  useEffect(() => {
    document.documentElement.lang = lang;
  }, [lang]);
  const setLang = (l: Lang) => {
    setLangState(l);
    try {
      localStorage.setItem("certower.lang", l);
    } catch {
      // ignore
    }
  };
  const t = (s: string, vars?: Record<string, string | number>) => {
    let out = dictionaries[lang][s] ?? s;
    if (vars) for (const [k, v] of Object.entries(vars)) out = out.replaceAll(`{${k}}`, String(v));
    return out;
  };
  return <Ctx.Provider value={{ lang, setLang, t }}>{children}</Ctx.Provider>;
}

export function useI18n(): I18n {
  const c = useContext(Ctx);
  if (!c) throw new Error("useI18n outside I18nProvider");
  return c;
}

// LanguagePicker switches the UI language.
export function LanguagePicker({ className }: { className?: string }) {
  const { lang, setLang } = useI18n();
  return (
    <select className={className} aria-label="Language / 語言 / 语言" value={lang} onChange={(e) => setLang(e.target.value as Lang)}>
      {languages.map((l) => (
        <option key={l.code} value={l.code}>
          {l.name}
        </option>
      ))}
    </select>
  );
}
