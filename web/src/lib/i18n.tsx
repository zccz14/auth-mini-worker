import { createContext, createElement, useCallback, useContext, useMemo, useState, type ReactNode } from 'react';

/**
 * Flat key-to-pair dictionary, no nested maps and no lazy loading: the bundle cannot build with a
 * missing translation because the array index is part of the type.
 */
export const messages = {
  'app.name': ['Auth Mini', 'Auth Mini'],
  'app.tagline': ['一个身份，通行所有产品。', 'One identity across every product.'],
  'language.toggle': ['切换语言', 'Switch language'],
  'language.zh': ['中文', 'Chinese'],
  'language.en': ['English', 'English'],
  'login.title': ['登录', 'Sign in'],
  'login.subtitle': ['使用邮箱验证码或通行密钥登录。', 'Sign in with an email code or a passkey.'],
  'login.email.label': ['邮箱', 'Email'],
  'login.email.placeholder': ['you@example.com', 'you@example.com'],
  'login.email.send': ['发送验证码', 'Send code'],
  'login.code.label': ['验证码', 'Verification code'],
  'login.code.placeholder': ['6 位数字', '6-digit code'],
  'login.code.verify': ['验证并登录', 'Verify and sign in'],
  'login.code.resend': ['重新发送', 'Send again'],
  'login.code.sent': ['验证码已发送到 {email}', 'A code is on its way to {email}'],
  'login.passkey': ['使用通行密钥', 'Use a passkey'],
  'login.passkey.hint': ['用指纹、面容或设备 PIN 直接确认。', 'Confirm with fingerprint, face or device PIN.'],
  'login.or': ['或', 'or'],
  'login.busy': ['处理中…', 'Working…'],
  'login.failed': ['登录失败，请重试。', 'Sign-in failed. Try again.'],
  'login.expired': ['登录状态已失效，请重新登录后继续。', 'That session is no longer valid. Sign in again to continue.'],
  'login.invalidRequest': ['登录链接无效：{reason}', 'This sign-in link is invalid: {reason}'],
  'login.reason.invalid_redirect_uri': ['回调地址不是有效的 http 或 https URL。', 'The callback is not a valid http or https URL.'],
  'login.reason.audience_rules': ['aud / audiences 参数不符合规则，或未包含回调域名。', 'The aud / audiences parameters break the rules or omit the callback host.'],
  'login.reason.https_required': ['非本地回环的回调必须使用 HTTPS。', 'Only loopback callbacks may use plain HTTP.'],
  'authorize.title': ['继续前往 {target}', 'Continue to {target}'],
  'authorize.body': ['将使用你的 Auth Mini 账号为它签发独立会话。', 'A separate session will be issued for it from your Auth Mini account.'],
  'authorize.loopback': ['本地开发应用 {host}', 'Local development app {host}'],
  'authorize.scope': ['请求访问 {audiences}', 'Requests access to {audiences}'],
  'authorize.continue': ['继续', 'Continue'],
  'authorize.signInFirst': ['请先登录，再继续。', 'Sign in first to continue.'],
  'home.title': ['已登录', 'Signed in'],
  'home.signedInAs': ['当前账号：{email}', 'Signed in as {email}'],
  'home.signOut': ['退出登录', 'Sign out'],
  'home.signIn': ['去登录', 'Sign in'],
  'home.notSignedIn': ['尚未登录。', 'Not signed in.'],
  'common.back': ['返回', 'Back'],
} satisfies Record<string, readonly [string, string]>;

export type MessageKey = keyof typeof messages;
export type Language = 'zh' | 'en';

interface I18nValue {
  lang: Language;
  setLang: (lang: Language) => void;
  t: (key: MessageKey, vars?: Record<string, string>) => string;
}

const STORAGE_KEY = 'auth-mini.lang';
const I18nContext = createContext<I18nValue | null>(null);

function initialLanguage(): Language {
  const stored = typeof localStorage === 'undefined' ? null : localStorage.getItem(STORAGE_KEY);
  if (stored === 'zh' || stored === 'en') return stored;
  return typeof navigator !== 'undefined' && navigator.language.startsWith('zh') ? 'zh' : 'en';
}

export function I18nProvider({ children }: { children: ReactNode }) {
  const [lang, setLanguage] = useState<Language>(initialLanguage);

  const setLang = useCallback((next: Language) => {
    setLanguage(next);
    try {
      localStorage.setItem(STORAGE_KEY, next);
    } catch {
      // Storage can be unavailable in private modes; the language still applies to this tab.
    }
  }, []);

  const value = useMemo<I18nValue>(() => {
    const t = (key: MessageKey, vars?: Record<string, string>) => {
      const [zh, en] = messages[key];
      const text = lang === 'zh' ? zh : en;
      if (!vars) return text;
      return Object.entries(vars).reduce((acc, [name, replacement]) => acc.replaceAll(`{${name}}`, replacement), text);
    };
    return { lang, setLang, t };
  }, [lang, setLang]);

  return createElement(I18nContext.Provider, { value }, children);
}

export function useI18n(): I18nValue {
  const value = useContext(I18nContext);
  if (value === null) throw new Error('useI18n must be used inside I18nProvider');
  return value;
}
