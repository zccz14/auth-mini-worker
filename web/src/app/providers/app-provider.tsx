import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useState,
  type PropsWithChildren,
} from 'react';
import { AuthMiniProvider, useAuthMini } from 'auth-mini-react-components';
import { resolveServerBaseUrl } from '@/lib/app-config';
import {
  extendAppSdk,
  type AdminSetupState,
  type AppSdk,
  type Branding,
} from '@/lib/app-sdk';

const ANONYMOUS_SESSION = {
  status: 'anonymous',
  authenticated: false,
  sessionId: null,
  accessToken: null,
  refreshToken: null,
  receivedAt: null,
  expiresAt: null,
} as const;

type AppContextValue = {
  sdk: AppSdk | null;
  /** Public branding, readable without a session and after the instance is claimed. */
  branding: Branding | null;
  setupState: AdminSetupState | null;
  /** True when an administrator exists, even if that state arrived as a 403. */
  setupInitialized: boolean;
  setupLoading: boolean;
  setupError: string;
  reloadSetupState: () => Promise<void>;
};

/**
 * `/admin/setup` is gated on loopback in the legacy server, so a Worker has to gate it on
 * "no admin exists yet" instead. Once somebody claims the administrator, the endpoint answers
 * 403 `admin_setup_forbidden` — that is the server reporting "already done", not a failure.
 */
function isAdminSetupForbidden(cause: unknown): boolean {
  if (typeof cause !== 'object' || cause === null) return false;
  const candidate = cause as { status?: unknown; error?: unknown };
  return candidate.status === 403 && candidate.error === 'admin_setup_forbidden';
}

const AppContext = createContext<AppContextValue | null>(null);

export function AppProvider({ children }: PropsWithChildren) {
  const [serverBaseUrl] = useState(() =>
    resolveServerBaseUrl(window.location.href),
  );

  return (
    <AuthMiniProvider
      authMiniBaseUrl={serverBaseUrl}
      autoRedirectToLogin={false}
    >
      <AppServicesProvider>{children}</AppServicesProvider>
    </AuthMiniProvider>
  );
}

function AppServicesProvider({ children }: PropsWithChildren) {
  const { sdk: browserSdk, authMiniBaseUrl } = useAuthMini();
  const sdk = useMemo(
    () => browserSdk && extendAppSdk(browserSdk, authMiniBaseUrl),
    [browserSdk, authMiniBaseUrl],
  );
  const [branding, setBranding] = useState<Branding | null>(null);
  const [setupState, setSetupState] = useState<AdminSetupState | null>(null);
  const [setupInitialized, setSetupInitialized] = useState(false);
  const [setupLoading, setSetupLoading] = useState(true);
  const [setupError, setSetupError] = useState('');

  async function loadSetupState(nextSdk: AppSdk, active = () => true) {
    setSetupLoading(true);
    setSetupError('');
    try {
      const nextSetupState = await nextSdk.admin.setup.fetch();
      if (active()) {
        setSetupState(nextSetupState);
        setSetupInitialized(Boolean(nextSetupState.admin_user_id));
      }
    } catch (cause) {
      if (!active()) return;
      if (isAdminSetupForbidden(cause)) {
        setSetupState(null);
        setSetupInitialized(true);
        setSetupError('');
        return;
      }
      setSetupState(null);
      setSetupInitialized(false);
      setSetupError(
        cause instanceof Error ? cause.message : 'Unable to load server setup.',
      );
    } finally {
      if (active()) setSetupLoading(false);
    }
  }

  useEffect(() => {
    if (!sdk) return;
    let active = true;
    void loadSetupState(sdk, () => active);
    return () => {
      active = false;
    };
  }, [sdk]);

  // Branding is cosmetic: a failure leaves the defaults on screen rather than an error state.
  useEffect(() => {
    if (!sdk?.branding) return;
    let active = true;
    void sdk.branding.fetch().then(
      (next) => {
        if (active) setBranding(next);
      },
      () => undefined,
    );
    return () => {
      active = false;
    };
  }, [sdk]);

  const brandName = branding?.brand_name ?? setupState?.brand_name ?? 'Auth Mini';
  useEffect(() => {
    // The tab is part of the brand: renaming the instance has to reach it too.
    document.title = brandName;
  }, [brandName]);

  return (
    <AppContext.Provider
      value={{
        sdk,
        branding,
        setupState,
        setupInitialized,
        setupLoading,
        setupError,
        reloadSetupState: async () => {
          if (sdk) await loadSetupState(sdk);
        },
      }}
    >
      {children}
    </AppContext.Provider>
  );
}

export function useApp() {
  const { session, authMiniBaseUrl } = useAuthMini();
  const value = useContext(AppContext);
  if (!value) throw new Error('useApp must be used inside AppProvider');
  return {
    ...value,
    serverBaseUrl: authMiniBaseUrl,
    session: session ?? ANONYMOUS_SESSION,
  };
}
