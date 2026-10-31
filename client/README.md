# client

Rust client core for wallets: registration over Oblivious HTTP, lease
renewal, hint list, and long-poll.

It does no networking itself. It builds and opens OHTTP messages, and the
host app sends them with its own HTTP stack (URLSession, OkHttp). Wallet SDKs
compile it into their existing native library and expose it through their
own FFI, so the app never links a second Rust library.
