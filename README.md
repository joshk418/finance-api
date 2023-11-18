# finance-api

Small API project used for personal finance site.

To run the project, you must specify a toml config file `go run main.go -cfg=<filename>.toml`

Config structure:
```toml
# name of the api, used in the route: http://<host>/<name>/auth...
Name = "xxxxx"

Host = "xxxxx"
Port = "xxxxx"
RequestTimeout = 15

# Key used with jwt package
JwtKey = "xxxxx"

# used to encrypt/decrypt jwt auth tokens
EncryptionKey = "xxxxx"

# Connection string
DbConnection = "xxxxx"
```