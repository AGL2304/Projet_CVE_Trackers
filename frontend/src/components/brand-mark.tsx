import type { SVGProps } from "react";

/**
 * CVE Tracker brand mark — the "severity gauge" dial.
 *
 * Self-contained colours from the charte graphique: a navy ring (#1E2A40)
 * with four severity arcs (low #3DDC84 → medium #FFD166 → high #FB8B24 →
 * critical #E63946), a navy hub and a light needle. Renders well on both the
 * light content surfaces and the dark sidebar.
 */
export function BrandMark({
  title = "CVE Tracker",
  ...props
}: SVGProps<SVGSVGElement> & { title?: string }) {
  return (
    <svg viewBox="0 0 200 200" role="img" aria-label={title} {...props}>
      <circle cx="100" cy="100" r="70" fill="none" stroke="#1E2A40" strokeWidth="16" />
      <path d="M50.5,149.5 A70,70 0 0 1 34.22,76.06" fill="none" stroke="#3DDC84" strokeWidth="16" strokeLinecap="round" />
      <path d="M36.56,70.42 A70,70 0 0 1 100,30" fill="none" stroke="#FFD166" strokeWidth="16" strokeLinecap="round" />
      <path d="M106.1,30.27 A70,70 0 0 1 165.78,76.06" fill="none" stroke="#FB8B24" strokeWidth="16" strokeLinecap="round" />
      <path d="M167.61,81.88 A70,70 0 0 1 145.0,153.62" fill="none" stroke="#E63946" strokeWidth="16" strokeLinecap="round" />
      <circle cx="100" cy="100" r="40" fill="#0B1220" />
      <line x1="100" y1="100" x2="138.3" y2="67.86" stroke="#EAF2FF" strokeWidth="5" strokeLinecap="round" />
      <circle cx="100" cy="100" r="7" fill="#EAF2FF" />
    </svg>
  );
}
