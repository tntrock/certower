// HTML pattern for slugs (organization, project, certificate names). The
// dash is escaped because browsers compile pattern with the "v" flag, where
// an unescaped "-" at the end of a character class is a syntax error and
// the whole pattern is silently ignored.
export const SLUG_PATTERN = "[a-z0-9]([a-z0-9\\-]{0,61}[a-z0-9])?";
