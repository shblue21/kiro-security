export type SortKey = "severity" | "confidence" | "updated" | "title";

export interface FindingLike {
  title: string;
  summary: string;
  severity: { level: string };
  confidence: { level: string };
  validationStatus: string;
  triageStatus: string;
  taxonomy: { category: string };
  locations: Array<{ path: string }>;
  updatedAt: string;
}

export interface FindingFilters {
  query: string;
  severity: string;
  confidence: string;
  validation: string;
  triage: string;
  sort: SortKey;
}

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };
const CONFIDENCE_ORDER: Record<string, number> = { high: 0, medium: 1, low: 2 };

export function filterAndSortFindings<T extends FindingLike>(findings: T[], filters: FindingFilters): T[] {
  const query = filters.query.trim().toLocaleLowerCase();
  return findings
    .filter((finding) => !filters.severity || finding.severity.level === filters.severity)
    .filter((finding) => !filters.confidence || finding.confidence.level === filters.confidence)
    .filter((finding) => !filters.validation || finding.validationStatus === filters.validation)
    .filter((finding) => !filters.triage || finding.triageStatus === filters.triage)
    .filter((finding) => {
      if (!query) return true;
      return [
        finding.title,
        finding.summary,
        finding.taxonomy.category,
        finding.locations[0]?.path ?? "",
      ].some((value) => value.toLocaleLowerCase().includes(query));
    })
    .sort((left, right) => {
      switch (filters.sort) {
        case "severity":
          return (SEVERITY_ORDER[left.severity.level] ?? 99) - (SEVERITY_ORDER[right.severity.level] ?? 99) || left.title.localeCompare(right.title);
        case "confidence":
          return (CONFIDENCE_ORDER[left.confidence.level] ?? 99) - (CONFIDENCE_ORDER[right.confidence.level] ?? 99) || left.title.localeCompare(right.title);
        case "title":
          return left.title.localeCompare(right.title);
        case "updated":
        default:
          return Date.parse(right.updatedAt) - Date.parse(left.updatedAt);
      }
    });
}

export function progressLabel(phase: string, overallPercent: number): string {
  const name = phase.replaceAll("_", " ");
  return `${name.charAt(0).toUpperCase()}${name.slice(1)} · ${Math.max(0, Math.min(100, Math.round(overallPercent)))}%`;
}
