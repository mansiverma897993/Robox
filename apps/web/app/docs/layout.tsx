import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Documentation — Robox",
  description: "Learn how to import, audit, understand, integrate, and extend Robox for Anchor, native Solana, and Rust smart-contract projects.",
  openGraph: {
    title: "Robox — Solana security, explained.",
    description: "Documentation for the Rust-native security auditor built for Anchor, native Solana, and Rust smart-contract projects.",
    type: "website",
    images: [{ url: "/robox-docs-og.png", width: 1536, height: 864, alt: "Robox documentation — Solana security, explained." }],
  },
  twitter: {
    card: "summary_large_image",
    title: "Robox — Solana security, explained.",
    description: "Documentation for the Rust-native Solana security auditor.",
    images: ["/robox-docs-og.png"],
  },
};

export default function DocsLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return children;
}
