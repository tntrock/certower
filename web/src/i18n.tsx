import { createContext, useContext, useState, type ReactNode } from "react";
import { zhTW } from "./locales/zh-TW";

// Strings are written in English in the code and looked up in a dictionary
// per language; a missing translation falls back to English.

export type Lang = "en" | "zh-TW";

const dictionaries: Record<Lang, Record<string, string>> = { en: {}, "zh-TW": zhTW };

function detect(): Lang {
  try {
    const saved = localStorage.getItem("certower.lang");
    if (saved === "en" || saved === "zh-TW") return saved;
  } catch {
    // storage unavailable
  }
  return navigator.language.toLowerCase().startsWith("zh") ? "zh-TW" : "en";
}

interface I18n {
  lang: Lang;
  setLang: (l: Lang) => void;
  t: (s: string, vars?: Record<string, string | number>) => string;
}

const Ctx = createContext<I18n | null>(null);

export function I18nProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<Lang>(detect);
  const setLang = (l: Lang) => {
    setLangState(l);
    try {
      localStorage.setItem("certower.lang", l);
    } catch {
      // ignore
    }
    document.documentElement.lang = l;
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
