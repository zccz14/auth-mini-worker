import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { api, ApiError, isTokenPair } from '@/lib/api';
import { useI18n } from '@/lib/i18n';
import { authorize, buildCallbackUrl, parseLoginRequest } from '@/lib/login-request';
import { clearSession, loadSession, saveTokens, type StoredSession } from '@/lib/session';
import { passkeySignIn } from '@/lib/webauthn';
import { Alert } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { LanguageButton } from '@/components/language-button';

type Phase = 'sign-in' | 'authorizing';

export function LoginRoute() {
  const { t } = useI18n();
  const [search] = useSearchParams();
  const navigate = useNavigate();

  const request = useMemo(
    () => parseLoginRequest(search.toString(), window.location.search),
    [search],
  );

  const [session, setSession] = useState<StoredSession | null>(() => loadSession());
  const [email, setEmail] = useState('');
  const [code, setCode] = useState('');
  const [codeSent, setCodeSent] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [phase, setPhase] = useState<Phase>('sign-in');
  const startedRef = useRef(false);

  const delegate = useCallback(
    async (current: StoredSession) => {
      if (request.status !== 'ready' || request.target.kind === 'self') return;
      setPhase('authorizing');
      setError(null);
      try {
        const tokens = await authorize(request.target, current.accessToken);
        // Leave the GUI entirely: the browser now belongs to the business app.
        window.location.assign(buildCallbackUrl({ redirectUri: request.target.redirectUri, state: request.state, tokens }));
      } catch (cause) {
        setPhase('sign-in');
        if (cause instanceof ApiError && cause.status === 401) {
          clearSession();
          setSession(null);
          setNotice(t('login.expired'));
          return;
        }
        setError(t('login.failed'));
      }
    },
    [request, t],
  );

  // Landing here with a live main-site session and a target app means "silent SSO": no form, just
  // the delegated session. The ref keeps React's double-invoked effects from asking twice.
  useEffect(() => {
    if (request.status !== 'ready' || request.target.kind === 'self') return;
    if (session === null || startedRef.current) return;
    startedRef.current = true;
    void delegate(session);
  }, [delegate, request, session]);

  const finish = useCallback(
    async (tokens: unknown, address: string | null) => {
      if (!isTokenPair(tokens)) {
        setError(t('login.failed'));
        return;
      }
      const stored = saveTokens(tokens, address);
      setSession(stored);
      if (request.status === 'ready' && request.target.kind !== 'self') {
        await delegate(stored);
        return;
      }
      navigate('/');
    },
    [delegate, navigate, request, t],
  );

  const sendCode = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      await api('/email/start', { method: 'POST', body: JSON.stringify({ email: email.trim() }) });
      setCodeSent(true);
      setNotice(t('login.code.sent', { email: email.trim() }));
    } catch {
      setError(t('login.failed'));
    } finally {
      setBusy(false);
    }
  }, [email, t]);

  const verifyCode = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      const tokens = await api('/email/verify', {
        method: 'POST',
        body: JSON.stringify({ email: email.trim(), code: code.trim() }),
      });
      await finish(tokens, email.trim());
    } catch {
      setError(t('login.failed'));
    } finally {
      setBusy(false);
    }
  }, [code, email, finish, t]);

  const signInWithPasskey = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      await finish(await passkeySignIn(), session?.email ?? null);
    } catch {
      setError(t('login.failed'));
    } finally {
      setBusy(false);
    }
  }, [finish, session?.email, t]);

  if (request.status === 'invalid') {
    return (
      <Shell title={t('login.title')} description={t('login.subtitle')}>
        <Alert variant="destructive">{t('login.invalidRequest', { reason: t(`login.reason.${request.reason}` as never) })}</Alert>
      </Shell>
    );
  }

  if (phase === 'authorizing' && request.target.kind !== 'self') {
    return (
      <Shell title={t('authorize.title', { target: request.target.displayHost })} description={t('authorize.body')}>
        <p className="text-sm text-muted-foreground">{t('login.busy')}</p>
      </Shell>
    );
  }

  const targetLabel = request.target.kind === 'self' ? null : request.target;

  return (
    <Shell title={t('login.title')} description={t('login.subtitle')}>
      <div className="space-y-5">
        {targetLabel !== null && (
          <Alert>
            <div className="space-y-1">
              <p className="font-medium">{t('authorize.title', { target: targetLabel.displayHost })}</p>
              <p className="text-xs">
                {targetLabel.kind === 'loopback' ? t('authorize.loopback', { host: targetLabel.displayHost }) : t('authorize.body')}
              </p>
              {targetLabel.audiences !== null && (
                <p className="text-xs text-muted-foreground">
                  {t('authorize.scope', { audiences: targetLabel.audiences.join(', ') })}
                </p>
              )}
            </div>
          </Alert>
        )}

        {notice !== null && <Alert>{notice}</Alert>}
        {error !== null && <Alert variant="destructive">{error}</Alert>}

        <div className="space-y-2">
          <Label htmlFor="email">{t('login.email.label')}</Label>
          <Input
            id="email"
            type="email"
            inputMode="email"
            autoComplete="email"
            placeholder={t('login.email.placeholder')}
            value={email}
            disabled={busy || codeSent}
            onChange={(event) => setEmail(event.target.value)}
          />
        </div>

        {!codeSent ? (
          <Button className="w-full" onClick={sendCode} disabled={busy || email.trim().length === 0}>
            {busy ? t('login.busy') : t('login.email.send')}
          </Button>
        ) : (
          <div className="space-y-3">
            <div className="space-y-2">
              <Label htmlFor="code">{t('login.code.label')}</Label>
              <Input
                id="code"
                inputMode="numeric"
                autoComplete="one-time-code"
                maxLength={6}
                placeholder={t('login.code.placeholder')}
                value={code}
                disabled={busy}
                onChange={(event) => setCode(event.target.value.replace(/\D/g, ''))}
              />
            </div>
            <Button className="w-full" onClick={verifyCode} disabled={busy || code.length !== 6}>
              {busy ? t('login.busy') : t('login.code.verify')}
            </Button>
            <Button variant="ghost" className="w-full" onClick={sendCode} disabled={busy}>
              {t('login.code.resend')}
            </Button>
          </div>
        )}

        <div className="flex items-center gap-3 text-xs uppercase tracking-wide text-muted-foreground">
          <span className="h-px flex-1 bg-border" />
          {t('login.or')}
          <span className="h-px flex-1 bg-border" />
        </div>

        <div className="space-y-2">
          <Button variant="outline" className="w-full" onClick={signInWithPasskey} disabled={busy}>
            {t('login.passkey')}
          </Button>
          <p className="text-center text-xs text-muted-foreground">{t('login.passkey.hint')}</p>
        </div>
      </div>
    </Shell>
  );
}

function Shell({ title, description, children }: { title: string; description: string; children: ReactNode }) {
  return (
    <main className="flex min-h-screen flex-col items-center justify-center bg-gradient-to-b from-background to-secondary/40 px-4 py-10">
      <div className="w-full max-w-md">
        <div className="mb-6 flex items-center justify-between">
          <Brand />
          <LanguageButton />
        </div>
        <Card>
          <CardHeader>
            <CardTitle>{title}</CardTitle>
            <CardDescription>{description}</CardDescription>
          </CardHeader>
          <CardContent>{children}</CardContent>
          <CardFooter className="justify-center text-xs text-muted-foreground">
            <span>{new URL('/', window.location.href).host}</span>
          </CardFooter>
        </Card>
      </div>
    </main>
  );
}

export function Brand() {
  const { t } = useI18n();
  return (
    <div className="flex flex-col">
      <span className="text-lg font-semibold tracking-tight">{t('app.name')}</span>
      <span className="text-xs text-muted-foreground">{t('app.tagline')}</span>
    </div>
  );
}
