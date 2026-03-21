-- PostgreSQL does not support removing values from an enum type.
-- The 'queued' value will remain in the enum but will not be used
-- after downgrade. This is safe because unused enum values have no
-- side effects.
SELECT 1;
