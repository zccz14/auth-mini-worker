import * as DropdownMenu from '@radix-ui/react-dropdown-menu';
import { useI18n, type Language } from '@/lib/i18n';
import { Button } from '@/components/ui/button';

const OPTIONS: Array<{ value: Language; labelKey: 'language.zh' | 'language.en' }> = [
  { value: 'zh', labelKey: 'language.zh' },
  { value: 'en', labelKey: 'language.en' },
];

/** IconButton + dropdown, per the frontend manual: the language control is never a bare select. */
export function LanguageButton() {
  const { lang, setLang, t } = useI18n();
  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger asChild>
        <Button variant="ghost" size="icon" aria-label={t('language.toggle')} title={t('language.toggle')}>
          <span className="text-base leading-none">{lang === 'zh' ? '文' : 'A'}</span>
        </Button>
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content
          align="end"
          sideOffset={6}
          className="z-50 min-w-32 overflow-hidden rounded-md border border-border bg-card p-1 shadow-md"
        >
          {OPTIONS.map((option) => (
            <DropdownMenu.Item
              key={option.value}
              onSelect={() => setLang(option.value)}
              className="cursor-pointer rounded-sm px-3 py-2 text-sm outline-none data-[highlighted]:bg-secondary"
            >
              {t(option.labelKey)}
            </DropdownMenu.Item>
          ))}
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  );
}
