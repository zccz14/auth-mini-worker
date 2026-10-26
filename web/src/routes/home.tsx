import { useCallback, useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '@/lib/api';
import { useI18n } from '@/lib/i18n';
import { clearSession, loadSession } from '@/lib/session';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { LanguageButton } from '@/components/language-button';
import { Brand } from '@/routes/login';

export function HomeRoute() {
  const { t } = useI18n();
  const [session, setSession] = useState(() => loadSession());

  const signOut = useCallback(async () => {
    if (session !== null) {
      try {
        await api('/session/logout', {
          method: 'POST',
          headers: { authorization: `Bearer ${session.accessToken}` },
        });
      } catch {
        // The local session is cleared either way; a dead token needs no apology.
      }
    }
    clearSession();
    setSession(null);
  }, [session]);

  return (
    <main className="flex min-h-screen flex-col items-center justify-center bg-gradient-to-b from-background to-secondary/40 px-4 py-10">
      <div className="w-full max-w-md">
        <div className="mb-6 flex items-center justify-between">
          <Brand />
          <LanguageButton />
        </div>
        <Card>
          <CardHeader>
            <CardTitle>{session === null ? t('home.notSignedIn') : t('home.title')}</CardTitle>
            <CardDescription>
              {session === null
                ? t('app.tagline')
                : t('home.signedInAs', { email: session.email ?? '—' })}
            </CardDescription>
          </CardHeader>
          <CardContent className="text-sm text-muted-foreground">
            <code className="text-xs">{session?.sessionId ?? ''}</code>
          </CardContent>
          <CardFooter className="gap-2">
            {session === null ? (
              <Button asChild className="w-full">
                <Link to="/login">{t('home.signIn')}</Link>
              </Button>
            ) : (
              <Button variant="outline" className="w-full" onClick={signOut}>
                {t('home.signOut')}
              </Button>
            )}
          </CardFooter>
        </Card>
      </div>
    </main>
  );
}
