# municipal

Register with TrueLayer and create an app client id and secret. Allow redirect URIs `http://localhost:3003/redirect`, `http://localhost:17465/redirect`, and `http://localhost:22496/redirect`.

Create a file `truelayer-sandbox.json` containing the TrueLayer client id and secret. For example:
```json
{
    "client_id": "sandbox-municipal-111111",
    "client_secret": "12f1a940-da45-464b-b803-53e8c95d3f2c"
}
```

Run using
```
cargo run
```

To use live bank information, create the file `truelayer-live.json` instead and run using
```
cargo run -- --live
```
