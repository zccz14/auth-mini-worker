import type { ReactNode } from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AppRouter } from '@/app/router';
import { I18nProvider } from '@/lib/i18n';
import { HomeRoute } from './home';
import { LoginRoute } from './login';
import { SetupRoute } from './setup';

const sdk = {
  admin: {
    config: { fetch: vi.fn(), save: vi.fn() },
    databaseUrl: () => 'https://auth.example.com/admin/database',
    jwks: { list: vi.fn(), rotate: vi.fn() },
    requestAudit: { fetch: vi.fn() },
    setup: { fetch: vi.fn(), initialize: vi.fn() },
    users: vi.fn(),
    directoryToken: {
      status: async () => ({ configured: false, created_at: null }),
    },
  },
  ed25519: { register: vi.fn(), start: vi.fn(), verify: vi.fn() },
  email: { start: vi.fn(), verify: vi.fn() },
  currentUser: {
    email: { startChange: vi.fn(), verifyChange: vi.fn() },
    fetch: vi.fn(),
  },
  passkey: { authenticate: vi.fn(), register: vi.fn() },
  session: {
    getState: vi.fn(),
    logout: vi.fn(),
    onChange: vi.fn(),
    refresh: vi.fn(),
  },
};

const reloadSetupState = vi.hoisted(() => vi.fn());

const sessionState = vi.hoisted(() => ({
  current: {
    accessToken: 'eyJhbGciOiJub25lIn0.eyJhdXRoX2FkbWluIjp0cnVlfQ.' as
      | string
      | null,
    authenticated: true as boolean,
    refreshToken: 'refresh-token' as string | null,
    sessionId: 'session-current' as string | null,
  },
}));

vi.mock('auth-mini-react-components', () => ({
  useAuthMini: () => ({ isReady: true, signOut: vi.fn() }),
}));

vi.mock('@/app/providers/app-provider', () => ({
  AppProvider: ({ children }: { children: ReactNode }) => children,
  useApp: () => ({
    serverBaseUrl: 'https://auth.example.com/',
    reloadSetupState,
    sdk,
    session: sessionState.current,
    setupError: '',
    setupInitialized: true,
    setupLoading: false,
    setupState: {
      admin_ed25519: null,
      admin_user_id: 'admin-user',
      brand_background_image: '',
      brand_name: 'auth-mini',
      issuer: 'https://auth.example.com',
      rp_id: 'auth.example.com',
      smtp: null,
    },
  }),
}));

function LocationProbe() {
  const location = useLocation();

  return (
    <output aria-label="Current location">
      {location.pathname + location.search + location.hash}
    </output>
  );
}

function renderRoute(ui: ReactNode) {
  return render(<I18nProvider>{ui}</I18nProvider>);
}

beforeEach(() => {
  sessionState.current = {
    accessToken: 'eyJhbGciOiJub25lIn0.eyJhdXRoX2FkbWluIjp0cnVlfQ.',
    authenticated: true,
    refreshToken: 'refresh-token',
    sessionId: 'session-current',
  };
});

afterEach(() => {
  localStorage.clear();
  document.documentElement.lang = 'en';
  vi.clearAllMocks();
  vi.restoreAllMocks();
});

describe('formal GUI routes', () => {
  it('renders the dedicated initialization page', () => {
    renderRoute(
      <MemoryRouter initialEntries={['/initialize']}>
        <SetupRoute />
      </MemoryRouter>,
    );

    expect(
      screen.getByRole('heading', { name: 'Initialize auth-mini' }),
    ).toBeInTheDocument();
    // The claim is a passkey registration, and the relying party is read from the address bar.
    expect(
      screen.getByRole('button', { name: 'Initialize with a passkey' }),
    ).toBeInTheDocument();
    expect(screen.getByText(window.location.hostname)).toBeInTheDocument();
    expect(screen.getByLabelText('Setup token')).toBeInTheDocument();
  });

  it('renders the dedicated login page with all sign-in methods', () => {
    sessionState.current = {
      accessToken: null,
      authenticated: false,
      refreshToken: null,
      sessionId: null,
    };

    renderRoute(
      <MemoryRouter
        initialEntries={[
          '/login?redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback',
        ]}
      >
        <LoginRoute />
      </MemoryRouter>,
    );

    expect(
      screen.getByRole('heading', { name: 'Sign in' }),
    ).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'Email' })).toBeInTheDocument();
    expect(screen.getAllByRole('tab').map((tab) => tab.textContent)).toEqual([
      'Email',
      'ED25519',
    ]);
    expect(
      screen.queryByRole('tab', { name: 'PassKey' }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: 'Sign In with PassKey' }),
    ).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'ED25519' })).toBeInTheDocument();
  });

  it('switches the login form to Chinese without leaving the route', async () => {
    const user = userEvent.setup();
    renderRoute(
      <MemoryRouter initialEntries={['/login']}>
        <LoginRoute />
      </MemoryRouter>,
    );

    await user.selectOptions(screen.getByLabelText('Language'), 'zh-CN');

    expect(screen.getByRole('heading', { name: '登录' })).toBeInTheDocument();
    expect(screen.getByLabelText('邮箱地址')).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: '发送邮箱验证码' }),
    ).toBeInTheDocument();
  });

  it('renders the home page with credential and session management', async () => {
    sdk.currentUser.fetch.mockResolvedValue({
      active_sessions: [
        {
          auth_method: 'webauthn',
          aud: 'portal.example.com',
          created_at: '2026-08-08T00:00:00Z',
          expires_at: '2026-08-15T00:00:00Z',
          id: 'session-mobile-layout',
          ip: '127.0.0.1',
          user_agent: 'Auth Mini mobile layout test',
        },
        {
          auth_method: 'email_otp',
          aud: '',
          created_at: '2026-08-08T00:00:00Z',
          expires_at: '2026-08-15T00:00:00Z',
          id: 'session-legacy-audience',
          ip: '127.0.0.1',
          user_agent: 'Auth Mini legacy audience test',
        },
      ],
      ed25519_credentials: [],
      email: 'user@example.com',
      user_id: 'user-1',
      webauthn_credentials: [],
    });

    const { container } = renderRoute(<HomeRoute />);

    expect(screen.getByRole('heading', { name: 'Email' })).toBeInTheDocument();
    expect(
      screen.getByRole('heading', { name: 'PassKey' }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole('heading', { name: 'ED25519' }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole('heading', { name: 'Active Sessions' }),
    ).toBeInTheDocument();
    expect(
      await screen.findByText('Verified email is active.'),
    ).toBeInTheDocument();
    expect(screen.getByText('session-mobile-layout')).toBeInTheDocument();
    expect(screen.getByText('portal.example.com')).toBeInTheDocument();
    expect(screen.getByText('Unavailable')).toBeInTheDocument();
    expect(screen.getAllByRole('button', { name: 'Kick' })).toHaveLength(2);
    expect(container.querySelector('tbody td > span')).toHaveTextContent(
      'Session ID',
    );
  });

  it('renders each home card as an isolated route section', async () => {
    sdk.currentUser.fetch.mockResolvedValue({
      active_sessions: [],
      ed25519_credentials: [],
      email: 'user@example.com',
      user_id: 'user-1',
      webauthn_credentials: [],
    });

    renderRoute(<HomeRoute section="sessions" />);

    expect(
      await screen.findByRole('heading', { name: 'Active Sessions' }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole('heading', { name: 'Email' }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole('heading', { name: 'PassKey' }),
    ).not.toBeInTheDocument();
  });

  it('changes the account email only after the new email OTP is verified', async () => {
    const user = userEvent.setup();
    sdk.currentUser.fetch.mockResolvedValue({
      active_sessions: [],
      ed25519_credentials: [],
      email: 'user@example.com',
      user_id: 'user-1',
      webauthn_credentials: [],
    });
    sdk.currentUser.email.startChange.mockResolvedValue({ ok: true });
    sdk.currentUser.email.verifyChange.mockResolvedValue({ ok: true });

    renderRoute(<HomeRoute />);

    await screen.findByText('Verified email is active.');
    await user.type(
      screen.getByLabelText('New email address'),
      'new@example.com',
    );
    await user.click(
      screen.getByRole('button', { name: 'Send verification code' }),
    );

    expect(sdk.currentUser.email.startChange).toHaveBeenCalledWith({
      email: 'new@example.com',
    });
    expect(
      await screen.findByText(
        'A verification code was sent to the new email address.',
      ),
    ).toBeInTheDocument();

    await user.type(
      screen.getByLabelText('Email change verification code'),
      '123456',
    );
    await user.click(
      screen.getByRole('button', { name: 'Confirm email change' }),
    );

    await waitFor(() => {
      expect(sdk.currentUser.email.verifyChange).toHaveBeenCalledWith({
        code: '123456',
        email: 'new@example.com',
      });
    });
    expect(
      await screen.findByText('Your email address has been updated.'),
    ).toBeInTheDocument();
  });

  it('navigates between independent admin pages and preserves their actions', async () => {
    sdk.admin.config.fetch.mockResolvedValue({
      admin_ed25519: null,
      admin_user_id: 'admin-user',
      brand_background_image: '',
      brand_name: 'auth-mini',
      issuer: 'https://auth.example.com',
      rp_id: 'auth.example.com',
      smtp: null,
    });
    sdk.admin.jwks.list.mockResolvedValue({
      keys: [
        { slot: 'CURRENT', public_jwk: { kid: 'current-kid', kty: 'OKP' } },
        { slot: 'STANDBY', public_jwk: { kid: 'standby-kid', kty: 'OKP' } },
      ],
    });
    sdk.admin.jwks.rotate.mockResolvedValue({
      keys: [
        { slot: 'CURRENT', public_jwk: { kid: 'standby-kid', kty: 'OKP' } },
        {
          slot: 'STANDBY',
          public_jwk: { kid: 'fresh-standby-kid', kty: 'OKP' },
        },
      ],
    });
    sdk.admin.config.save.mockResolvedValue({
      admin_ed25519: null,
      admin_user_id: 'admin-user',
      brand_background_image: 'https://cdn.example.com/login.jpg',
      brand_name: 'Example Auth',
      issuer: 'https://auth.example.com',
      rp_id: 'auth.example.com',
      smtp: null,
    });
    sdk.admin.users.mockResolvedValue({
      users: [
        {
          id: 'user-42',
          email: 'member@example.com',
          active_session_count: 2,
          passkey_count: 1,
          ed25519_count: 0,
        },
      ],
    });
    sdk.admin.requestAudit.fetch.mockResolvedValue({
      started_at: 1_784_200_000,
      window_seconds: 86_400,
      endpoints: [
        { method: 'POST', endpoint: '/email/start', count: 12, error_count: 2, mean_ms: 31 },
        { method: 'GET', endpoint: '/jwks', count: 3, error_count: 0, mean_ms: 2 },
      ],
      unmatched: [
        {
          method: 'GET',
          path: '/wp-login.php',
          count: 42,
          last_seen: 1_784_199_000,
        },
      ],
    });
    const user = userEvent.setup();

    render(
      <MemoryRouter initialEntries={['/admin']}>
        <AppRouter />
        <LocationProbe />
      </MemoryRouter>,
    );

    expect(
      screen.getByRole('heading', { name: 'Admin overview', level: 2 }),
    ).toBeInTheDocument();
    expect(await screen.findByText('admin-user')).toBeInTheDocument();
    // The overview reads the administrator view: the first-run payload is gated after the claim.
    expect(sdk.admin.config.fetch).toHaveBeenCalledTimes(1);
    expect(sdk.admin.jwks.list).not.toHaveBeenCalled();
    expect(sdk.admin.users).not.toHaveBeenCalled();
    expect(sdk.admin.requestAudit.fetch).not.toHaveBeenCalled();
    expect(
      screen.queryByRole('button', { name: 'Save configuration' }),
    ).not.toBeInTheDocument();

    await user.click(screen.getByRole('link', { name: 'Configuration' }));
    await waitFor(() =>
      expect(screen.getByLabelText('Brand name')).toHaveValue('auth-mini'),
    );
    expect(
      screen.queryByRole('button', { name: 'JWK Rotate' }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole('link', { name: 'Admin overview' }),
    ).not.toHaveAttribute('aria-current');
    expect(screen.getByRole('link', { name: 'Configuration' })).toHaveAttribute(
      'aria-current',
      'page',
    );

    await user.clear(screen.getByLabelText('Brand name'));
    await user.type(screen.getByLabelText('Brand name'), 'Example Auth');
    await user.selectOptions(screen.getByLabelText('Language'), 'zh-CN');
    expect(screen.getByLabelText('品牌名称')).toHaveValue('Example Auth');
    expect(sdk.admin.config.fetch).toHaveBeenCalledTimes(2);
    await user.selectOptions(screen.getByLabelText('语言'), 'en');
    await user.type(
      screen.getByLabelText('Brand background image'),
      'https://cdn.example.com/login.jpg',
    );
    await user.click(
      screen.getByRole('button', { name: 'Save configuration' }),
    );

    await waitFor(() =>
      expect(sdk.admin.config.save).toHaveBeenCalledWith({
        issuer: 'https://auth.example.com',
        rp_id: 'auth.example.com',
        brand_name: 'Example Auth',
        brand_background_image: 'https://cdn.example.com/login.jpg',
        smtp: null,
      }),
    );
    await waitFor(() => expect(reloadSetupState).toHaveBeenCalledOnce());

    await user.click(screen.getByRole('link', { name: 'JWKs' }));
    expect(await screen.findByText('CURRENT')).toBeInTheDocument();
    expect(screen.getByText('STANDBY')).toBeInTheDocument();
    expect(screen.queryByLabelText('Brand name')).not.toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'JWK Rotate' }));

    expect(sdk.admin.jwks.rotate).toHaveBeenCalledOnce();
    expect(await screen.findByText(/fresh-standby-kid/)).toBeInTheDocument();

    await user.click(screen.getByRole('link', { name: 'Request audit' }));
    expect(await screen.findByText('/email/start')).toBeInTheDocument();
    expect(screen.getByText('12')).toBeInTheDocument();
    expect(screen.getByText('/jwks')).toBeInTheDocument();
    expect(screen.getByText('3')).toBeInTheDocument();
    expect(screen.getByText('Unknown endpoints')).toBeInTheDocument();
    expect(screen.getByText('/wp-login.php')).toBeInTheDocument();
    expect(screen.getByText('42')).toBeInTheDocument();
    expect(screen.getByLabelText('Current location')).toHaveTextContent(
      '/admin/request-audit',
    );
    expect(sdk.admin.requestAudit.fetch).toHaveBeenCalledOnce();
    expect(screen.queryByText('CURRENT')).not.toBeInTheDocument();

    await user.click(screen.getByRole('link', { name: 'Users' }));
    expect(await screen.findByText('member@example.com')).toBeInTheDocument();
    expect(screen.queryByText('CURRENT')).not.toBeInTheDocument();
    expect(
      screen
        .getAllByRole('link')
        .filter((link) => link.getAttribute('aria-current') === 'page'),
    ).toHaveLength(1);

    await user.selectOptions(screen.getByLabelText('Language'), 'zh-CN');
    expect(
      screen.getByRole('heading', { name: '用户', level: 1 }),
    ).toBeInTheDocument();
    expect(screen.getByRole('link', { name: '管理概览' })).toBeInTheDocument();
  });

  it.each([
    ['/admin/configuration', () => sdk.admin.config.fetch],
    ['/admin/jwks', () => sdk.admin.jwks.list],
    ['/admin/request-audit', () => sdk.admin.requestAudit.fetch],
    ['/admin/users', () => sdk.admin.users],
  ] as const)(
    'shows loading failures on %s without exposing other cards',
    async (path, query) => {
      query().mockRejectedValueOnce(new Error('Service unavailable'));
      render(
        <MemoryRouter initialEntries={[path]}>
          <AppRouter />
        </MemoryRouter>,
      );
      expect(await screen.findByRole('alert')).toHaveTextContent(
        'Service unavailable',
      );
      expect(screen.queryByRole('status')).not.toBeInTheDocument();
      expect(
        screen.queryByRole('button', { name: 'Save configuration' }),
      ).not.toBeInTheDocument();
    },
  );

  it('redirects unknown pages to the default page', async () => {
    sdk.currentUser.fetch.mockResolvedValue({
      active_sessions: [],
      ed25519_credentials: [],
      email: 'user@example.com',
      user_id: 'user-1',
      webauthn_credentials: [],
    });

    render(
      <MemoryRouter initialEntries={['/missing/page?next=%2Fadmin#setup']}>
        <AppRouter />
        <LocationProbe />
      </MemoryRouter>,
    );

    expect(
      await screen.findByRole('heading', { name: 'Email' }),
    ).toBeInTheDocument();
    expect(screen.getByLabelText('Current location')).toHaveTextContent('/');
  });
});
