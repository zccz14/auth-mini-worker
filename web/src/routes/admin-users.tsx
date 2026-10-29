import { useEffect, useState } from 'react';
import { DirectoryTokenCard } from '@/components/app/directory-token-card';
import { useApp } from '@/app/providers/app-provider';
import { useI18n } from '@/lib/i18n';
import { Alert, AlertDescription } from '@/components/ui/alert';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';

export function AdminUsersRoute() {
  const { sdk } = useApp();
  const { t } = useI18n();
  const [users, setUsers] = useState<Array<Record<string, unknown>> | null>(
    null,
  );
  const [loadError, setLoadError] = useState<string | null>(null);
  const errorMessage =
    loadError === null ? '' : loadError || t('admin.loadError');

  useEffect(() => {
    if (!sdk) return;
    let active = true;
    void sdk.admin.users().then(
      (result) => {
        if (active) {
          setUsers(result.users);
          setLoadError(null);
        }
      },
      (cause) => {
        if (active) setLoadError(cause instanceof Error ? cause.message : '');
      },
    );
    return () => {
      active = false;
    };
  }, [sdk]);

  return (
    <div className="grid gap-4">
      <DirectoryTokenCard />
      <Card className="rounded-lg">
        <CardHeader>
          <CardTitle>{t('admin.users')}</CardTitle>
          <CardDescription>{t('admin.usersDescription')}</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-4">
          {errorMessage ? (
            <Alert>
              <AlertDescription>{errorMessage}</AlertDescription>
            </Alert>
          ) : null}
          {!users && loadError === null ? (
            <p role="status">{t('common.loading')}</p>
          ) : null}
          {users?.length === 0 ? <p>{t('admin.noUsers')}</p> : null}
          {users && users.length > 0 ? (
            <div
              className="overflow-x-auto"
              role="region"
              aria-label={t('admin.users')}
              tabIndex={0}
            >
              <table className="min-w-full whitespace-nowrap text-sm">
                <thead>
                  <tr className="border-b text-left text-slate-500">
                    <th className="p-2">{t('admin.user')}</th>
                    <th className="p-2">{t('common.email')}</th>
                    <th className="p-2">{t('admin.sessions')}</th>
                    <th className="p-2">{t('admin.passkeys')}</th>
                    <th className="p-2">ED25519</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map((user) => (
                    <tr
                      key={String(user.id)}
                      className="border-b border-slate-100"
                    >
                      <td className="p-2 font-mono">{String(user.id)}</td>
                      <td className="p-2">{String(user.email ?? '')}</td>
                      <td className="p-2">
                        {String(user.active_session_count ?? 0)}
                      </td>
                      <td className="p-2">{String(user.passkey_count ?? 0)}</td>
                      <td className="p-2">{String(user.ed25519_count ?? 0)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : null}
        </CardContent>
      </Card>
    </div>
  );
}
