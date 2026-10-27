import { useEffect, useState } from 'react';
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
import type { AdminSetupState } from '@/lib/app-sdk';

/**
 * The administrator overview.
 *
 * It reads `/admin/config`, not `/admin/setup`: the first-run payload is gated on "no root user
 * yet", so after the claim it answers 403 and every field here would read "Unavailable" forever.
 * The configuration endpoint is the same one this screen's sibling edits, and it needs exactly the
 * admin token that also guards this route.
 */
export function AdminRoute() {
  const { sdk } = useApp();
  const { t } = useI18n();
  const [settings, setSettings] = useState<AdminSetupState | null>(null);
  const [loadError, setLoadError] = useState('');

  useEffect(() => {
    if (!sdk) return;
    let active = true;
    void sdk.admin.config.fetch().then(
      (nextSettings) => {
        if (active) {
          setSettings(nextSettings);
          setLoadError('');
        }
      },
      (cause) => {
        if (active) {
          setLoadError(cause instanceof Error ? cause.message : '');
        }
      },
    );
    return () => {
      active = false;
    };
  }, [sdk]);

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t('admin.overview')}</CardTitle>
        <CardDescription>{t('admin.overviewDescription')}</CardDescription>
      </CardHeader>
      <CardContent className="grid gap-4">
        {loadError ? (
          <Alert>
            <AlertDescription>
              {loadError || t('admin.loadError')}
            </AlertDescription>
          </Alert>
        ) : null}
        <dl className="grid gap-4 text-sm text-slate-700">
          <div className="grid gap-1 sm:grid-cols-[10rem_minmax(0,1fr)]">
            <dt>{t('admin.userId')}</dt>
            <dd className="break-all font-mono">
              {settings?.admin_user_id ?? t('common.unavailable')}
            </dd>
          </div>
          <div className="grid gap-1 sm:grid-cols-[10rem_minmax(0,1fr)]">
            <dt>{t('common.issuer')}</dt>
            <dd className="break-all">
              {settings?.issuer ?? t('common.unavailable')}
            </dd>
          </div>
          <div className="grid gap-1 sm:grid-cols-[10rem_minmax(0,1fr)]">
            <dt>{t('common.rpId')}</dt>
            <dd className="break-all">
              {settings?.rp_id ?? t('common.unavailable')}
            </dd>
          </div>
        </dl>
      </CardContent>
    </Card>
  );
}
