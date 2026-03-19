# tcrypt-pack

CLI tool that encrypts plaintext values and stores them in the Suitcase section of a JSON config file. .NET 10 native AOT binary.

## What it does

Takes a plaintext value (connection string, API key, etc.), encrypts it using the TPM-backed Suitcase key, and writes the encrypted value into a JSON config file — all in one command. The config file is updated in place; only the specified key is touched.

## Usage

```bash
sudo tcrypt-pack --file <config.json> --key <name> --value <plaintext>
```

**Required:**

| Argument | Description |
|----------|-------------|
| `--file` | Path to the JSON config file (must already contain a `Suitcase` section) |
| `--key` | Key name within the Suitcase section to update (must already exist) |
| `--value` | Plaintext value to encrypt and store |

**Optional:**

| Argument | Default | Description |
|----------|---------|-------------|
| `--cred-path` | `/etc/credstore.encrypted/suitcase-key.cred` | Path to the TPM-sealed credential file |
| `--cred-name` | `suitcase-key` | Credential name embedded in the `.cred` file |

## How it works

1. **Unseal the Suitcase key** — calls `sudo systemd-creds decrypt` to extract the 32-byte AES key from the TPM-sealed credential file
2. **Encrypt the value** — uses `SuitcaseCrypt.Encrypt()` from [tcrypt-lib](https://github.com/RickAtSnowcap/tcrypt-lib) (AES-256-GCM authenticated encryption)
3. **Update the config file** — reads the JSON, replaces the specified key's value in the `Suitcase` section with the encrypted string, writes back with formatting preserved

## Example

```bash
sudo tcrypt-pack \
  --file /opt/myapp/appsettings.json \
  --key DbConnection \
  --value "Server=db.local;Database=mydb;User=app;Password=secret"
```

Resulting config:

```json
{
  "Suitcase": {
    "DbConnection": "Base64-encoded-encrypted-value-here"
  }
}
```

## Requirements

- .NET 10
- Linux with systemd and TPM 2.0
- Passwordless sudo (for `systemd-creds` TPM access)
- [tcrypt-lib](https://github.com/RickAtSnowcap/tcrypt-lib) (project reference)

## Build

```bash
dotnet publish TcryptPack.csproj -c Release -o publish
```

Produces a self-contained native binary at `publish/tcrypt-pack` (~2.6 MB). No .NET runtime required on the target machine.

## License

MIT
