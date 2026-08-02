import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Submit a Project — Robox",
  description: "Request a professional security audit for an Anchor, native Solana, SVM, or Rust smart-contract project.",
};

export default function SubmitLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return children;
}
