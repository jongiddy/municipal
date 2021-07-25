# municipal

Example code to obtain bank balances using the [TrueLayer](https://truelayer.com/) API.

1. Register with TrueLayer and create an app client id and secret. Allow redirect URIs `http://localhost:3003/redirect`, `http://localhost:17465/redirect`, and `http://localhost:22496/redirect`.

1. Create a file `truelayer-sandbox.json` containing the TrueLayer client id and secret. For example:
    ```json
    {
        "client_id": "sandbox-municipal-111111",
        "client_secret": "12f1a940-da45-464b-b803-53e8c95d3f2c"
    }
    ```

1. Run on sandbox account using
    ```
    cargo run
    ```

    Complete the login through the web browser then return to the terminal to see the output:
    ```
    TRANSACTION ACCOUNT 1 01-21-31 10000000 GBP26
    SAVINGS ACCOUNT 1 01-21-31 20000000 GBP52
    TRANSACTION ACCOUNT 2 01-21-31 30000000 GBP78
    SAVINGS ACCOUNT 2 01-21-31 40000000 GBP104
    TRANSACTION ACCOUNT 3 01-21-31 50000000 GBP130
    ```

To use for real bank information, create the file `truelayer-live.json` instead and run using
```
cargo run -- --live
```
