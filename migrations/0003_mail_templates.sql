-- Configurable mail templates.
--
-- The two transactional mails used to be hardcoded strings, including the instance's own name.
-- They are now templates with `{brand}`, `{code}` and `{minutes}` placeholders, so a renamed
-- instance mails its own name without anyone editing a template.
--
-- An empty string means "no opinion": the built-in default in `src/mail/template.ts` stands. That
-- is also why the columns default to '' rather than to the default wording — the wording can then
-- improve without a data migration, and existing rows keep behaving exactly as before.

ALTER TABLE app_meta ADD COLUMN login_mail_subject TEXT NOT NULL DEFAULT '';
ALTER TABLE app_meta ADD COLUMN login_mail_text TEXT NOT NULL DEFAULT '';
ALTER TABLE app_meta ADD COLUMN email_change_mail_subject TEXT NOT NULL DEFAULT '';
ALTER TABLE app_meta ADD COLUMN email_change_mail_text TEXT NOT NULL DEFAULT '';
