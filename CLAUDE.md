# E2EE P2P Messenger

End-to-end encrypted peer-to-peer messaging platform. TypeScript monorepo.

## Quick Ref
- **Dev**: `npm run dev` (starts server + web concurrently)
- **Build**: `npm run build`
- **Test**: `npm run test` (crypto + server tests)
- **Typecheck**: `npm run typecheck`
- **Demo**: `npm run demo`
- **GitHub**: lance-fisher/e2ee-messenger

## Monorepo Structure
```
apps/
  web/       — Next.js 14 PWA frontend (Tailwind CSS)
  server/    — Express relay + rendezvous server
packages/
  crypto/    — X3DH key exchange, Double Ratchet protocol, WebAuthn vault
docs/        — Protocol specs, threat model, API docs
scripts/     — Demo scripts
```

## Stack
- **Frontend**: Next.js 14, Tailwind CSS, TypeScript
- **Server**: Express, SQLite
- **Crypto**: libsodium-wrappers, OpenPGP.js
- **Auth**: WebAuthn (passwordless, biometric)
- **Communication**: WebRTC (P2P), WebSocket (relay fallback)
- **Testing**: Vitest (44 tests)

## Security Architecture
- X3DH key exchange for initial handshake
- Double Ratchet protocol for forward secrecy
- WebAuthn-based local vault for key storage
- No server-side message storage — relay only
