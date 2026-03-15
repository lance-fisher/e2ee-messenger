import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'E2EE Messenger',
  description: 'End-to-end encrypted peer-to-peer messaging',
  openGraph: {
    title: 'E2EE Messenger',
    description: 'End-to-end encrypted peer-to-peer messaging with X3DH key exchange, Double Ratchet protocol, and WebAuthn vault.',
    type: 'website',
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script
          dangerouslySetInnerHTML={{
            __html: `
              (function() {
                const theme = localStorage.getItem('theme');
                if (theme === 'dark' || (!theme && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
                  document.documentElement.classList.add('dark');
                }
              })();
            `,
          }}
        />
      </head>
      <body className="min-h-screen antialiased">
        {children}
      </body>
    </html>
  );
}
