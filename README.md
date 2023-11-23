# Go + HTMX + Web3

A very simple example HTMX with Web3 with:

- Go HTML templating engine.
- HTMX solution for SSR.
- Ethereum as authenticator.
- (+CSRF protection measures for all requests).
- SQLite3 with sqlc and golang-migrate.

## Motivation

For the hype.

## Usage

1. Set the necessary parameters or environment variables:

   ```shell
   ## .env.local
   ## A 32 bytes hex secret ()
   CSRF_SECRET=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
   ## A hex ECDSA private key in ethereum format (32 bytes)
   PRIVATE_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
   ## A unique string secret
   JWT_SECRET=secret
   ## PUBLIC_URL will be used as redirect url which is ${PUBLIC_URL}/callback
   PUBLIC_URL=http://localhost:3000
   DB_PATH=/data/db.sqlite3
   ```

2. Run the binary:

   ```shell
   ./auth-web3-htmx
   ```

**Help**:

```
NAME:
   auth-web3-htmx - Demo of Auth and HTMX.

USAGE:
   auth-web3-htmx [global options] command [command options] [arguments...]

COMMANDS:
   help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --csrf.secret value            A 32 bytes hex secret [$CSRF_SECRET]
   --jwt.secret value             A unique string secret [$JWT_SECRET]
   --config.path value, -c value  Path of the configuration file. (default: "./config.yaml") [$CONFIG_PATH]
   --public-url value             An URL pointing to the server. (default: "http://localhost:3000") [$PUBLIC_URL]
   --db.path value                SQLite3 database file path. (default: "./db.sqlite3") [$DB_PATH]
   --help, -h                     show help
   --version, -v                  print the version
```

## Application Flow

- A home page:
  - Show login button if not logged in.
  - Else, show a welcome with routing.
- A protected counter page.
