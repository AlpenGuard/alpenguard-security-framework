# AlpenGuard (VS Code Extension)

Early-release VS Code extension for AlpenGuard.

## Features

- Trace Explorer: ping/list/get traces from the AlpenGuard Compliance Oracle.
- Secure token storage: bearer token is stored in VS Code SecretStorage (not in the webview).

## Configuration

- `alpenguard.oracleUrl`: Oracle base URL (default `http://127.0.0.1:8787`)

## Commands

- `AlpenGuard: Open Trace Explorer`
- `AlpenGuard: Set Bearer Token`
- `AlpenGuard: Clear Bearer Token`
- `AlpenGuard: Ping Oracle`

## Development

1. Open the repo in VS Code.
2. In the extension folder:
   - `npm install`
   - `npm run build`
3. Press `F5` to launch the Extension Development Host.

## Security notes

- The webview does not receive or persist tokens.
- All requests are executed in the extension host and include `Authorization: Bearer ...` only when configured.
