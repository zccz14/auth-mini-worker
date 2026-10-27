import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useApp } from '@/app/providers/app-provider';
import { useI18n } from '@/lib/i18n';
import { readSetupToken, writeSetupToken } from '@/lib/setup-token';
import {
  decodeRegistrationOptions,
  serializeRegistrationCredential,
} from '@/lib/webauthn';

/**
 * `/initialize` — the one-time claim.
 *
 * It does exactly one thing: create the root user, with a passkey as its credential. The instance
 * has no administrator yet, so nothing here can be authorized by a session; the optional setup
 * token is the only shared secret involved.
 *
 * The relying party is read from the address bar rather than from the server, because the server
 * still says `localhost` until somebody claims it — and changing that needs the very
 * administrator this page creates. The owner confirms the two values before the passkey is made.
 */
export function SetupRoute() {
  const { reloadSetupState, sdk, setupError } = useApp();
  const { t } = useI18n();
  const navigate = useNavigate();
  const [token, setToken] = useState(() => readSetupToken());
  const [pending, setPending] = useState<'reload' | 'initialize' | null>(null);
  const [error, setError] = useState('');
  const [claimed, setClaimed] = useState(false);

  const issuer = window.location.origin;
  const rpId = window.location.hostname;
  const canInitialize = Boolean(sdk) && pending === null;

  async function reload() {
    setPending('reload');
    setError('');
    writeSetupToken(token);
    try {
      await reloadSetupState();
    } finally {
      setPending(null);
    }
  }

  async function initialize() {
    if (!sdk || pending !== null) return;
    if (typeof navigator === 'undefined' || typeof navigator.credentials?.create !== 'function') {
      setError(t('setup.passkeyUnsupported'));
      return;
    }

    setPending('initialize');
    setError('');
    writeSetupToken(token);

    try {
      const options = await sdk.admin.setup.passkeyOptions();
      const credential = (await navigator.credentials.create({
        publicKey: decodeRegistrationOptions(options.publicKey),
      })) as PublicKeyCredential | null;
      if (credential === null) throw new Error(t('setup.passkeyCancelled'));

      await sdk.admin.setup.initialize({
        request_id: options.request_id,
        credential: serializeRegistrationCredential(credential),
        issuer,
        rp_id: rpId,
      });
      setClaimed(true);

      // The claim only creates the administrator. Signing in is a separate ceremony, and it is
      // what puts this browser on the inside; a dismissed prompt costs one manual sign-in later.
      let signedIn = false;
      try {
        await sdk.passkey.authenticate();
        signedIn = true;
      } catch {
        signedIn = false;
      }
      await reloadSetupState();
      navigate(signedIn ? '/' : '/login', { replace: true });
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : t('setup.initializeError'));
    } finally {
      setPending(null);
    }
  }

  return (
    <div className="mx-auto w-full max-w-2xl">
      <Card className="rounded-lg">
        <CardHeader>
          <CardTitle>{t('setup.title')}</CardTitle>
          <CardDescription>{t('setup.description')}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-5">
          <div className="grid gap-2 rounded-md border border-slate-200 bg-slate-50 p-3 text-sm">
            <p className="font-medium text-slate-700">{t('setup.originTitle')}</p>
            <dl className="grid gap-1 text-slate-600">
              <div className="flex flex-wrap gap-2">
                <dt className="font-medium">{t('common.issuer')}</dt>
                <dd className="break-all font-mono">{issuer}</dd>
              </div>
              <div className="flex flex-wrap gap-2">
                <dt className="font-medium">{t('common.rpId')}</dt>
                <dd className="break-all font-mono">{rpId}</dd>
              </div>
            </dl>
            <p className="text-xs leading-5 text-slate-500">
              {t('setup.originHint')}
            </p>
          </div>

          <div className="grid gap-2">
            <Label htmlFor="setup-token">{t('setup.tokenLabel')}</Label>
            <Input
              id="setup-token"
              type="password"
              autoComplete="off"
              value={token}
              placeholder="ADMIN_SETUP_TOKEN"
              onChange={(event) => setToken(event.currentTarget.value)}
            />
            <p className="text-xs leading-5 text-slate-500">
              {t('setup.tokenHint')}
            </p>
          </div>

          {setupError ? (
            <Alert className="border-amber-200 bg-amber-50 text-amber-900">
              <AlertTitle>{t('common.unavailable')}</AlertTitle>
              <AlertDescription>{t('setup.tokenRequired')}</AlertDescription>
            </Alert>
          ) : null}

          {claimed ? (
            <Alert className="border-emerald-200 bg-emerald-50 text-emerald-900">
              <AlertTitle>{t('setup.claimed')}</AlertTitle>
            </Alert>
          ) : null}

          {error ? <p className="text-sm text-rose-600">{error}</p> : null}

          <div className="flex flex-wrap gap-3">
            <Button disabled={!canInitialize} onClick={() => void initialize()}>
              {pending === 'initialize'
                ? t('setup.initializing')
                : t('setup.passkeyButton')}
            </Button>
            <Button
              type="button"
              className="border border-slate-300 bg-white text-slate-700 hover:bg-slate-100"
              disabled={pending !== null}
              onClick={() => void reload()}
            >
              {pending === 'reload' ? t('common.loading') : t('setup.retry')}
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
