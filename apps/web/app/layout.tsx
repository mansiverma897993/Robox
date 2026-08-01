import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Robox — Solana Security Intelligence",
  description: "Fast, explainable security analysis for Solana and Anchor programs, powered by a Rust-native engine.",
  icons: { icon: "/favicon.svg", shortcut: "/favicon.svg" },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body>{children}</body></html>;
}

