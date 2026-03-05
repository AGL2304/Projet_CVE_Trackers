import type { Metadata } from "next";
import { JetBrains_Mono, Space_Grotesk } from "next/font/google";
import "./globals.css";
import { AppProviders } from "@/components/providers/app-providers";
import { AppShell } from "@/components/app-shell";

const primaryFont = Space_Grotesk({
  variable: "--font-geist-sans",
  subsets: ["latin"],
  display: "swap",
});

const monoFont = JetBrains_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
  display: "swap",
});

export const metadata: Metadata = {
  title: "CVE Tracker | Security Operations Frontend",
  description:
    "Plateforme SOC pour le suivi des CVEs, la gestion des actifs et le reporting cybersecurity.",
  keywords: ["CVE", "CVSS", "SOC", "cybersecurity", "vulnerability management"],
  authors: [{ name: "CVE Tracker Team" }],
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="fr" suppressHydrationWarning>
      <body
        className={`${primaryFont.variable} ${monoFont.variable} min-h-screen bg-background text-foreground antialiased`}
      >
        <AppProviders>
          <AppShell>{children}</AppShell>
        </AppProviders>
      </body>
    </html>
  );
}
