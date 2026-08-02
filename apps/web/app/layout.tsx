import type { Metadata } from "next";
import "./globals.css";
import "./features.css";

export const metadata: Metadata = {
  metadataBase: new URL(process.env.NEXT_PUBLIC_SITE_URL ?? "http://127.0.0.1:3000"),
  title: "Robox — Solana Security Intelligence",
  description: "Explainable security analysis for Anchor and native Solana programs, powered by a Rust-native engine.",
  icons: { icon: "/robox-logo-transparent.png", shortcut: "/robox-logo-transparent.png", apple: "/robox-logo-transparent.png" },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en" data-scroll-behavior="smooth" suppressHydrationWarning><body>{children}</body></html>;
}
