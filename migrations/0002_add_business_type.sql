-- Adds business_type to business_profile, captured during initial owner
-- signup rather than waiting for the full Settings form to be filled in.
-- Used to set sensible defaults (e.g. new items default to "service" for
-- a service-type business instead of "goods").

ALTER TABLE business_profile ADD COLUMN business_type TEXT;