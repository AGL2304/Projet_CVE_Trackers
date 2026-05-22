const DIACRITICS_REGEX = /[\u0300-\u036f]/g;
const WHITESPACE_REGEX = /\s+/g;

export function normalizeSearchTerm(value: string) {
  return value
    .normalize("NFD")
    .replace(DIACRITICS_REGEX, "")
    .toLowerCase()
    .replace(WHITESPACE_REGEX, " ")
    .trim();
}

export function includesSearchTerm(source: string, query: string) {
  const normalizedQuery = normalizeSearchTerm(query);
  if (!normalizedQuery) return true;

  return normalizeSearchTerm(source).includes(normalizedQuery);
}
