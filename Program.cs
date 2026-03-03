using System.Diagnostics;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using Snowcap.TCrypt;

namespace TcryptPack;

/// <summary>
/// tcrypt-pack — Snowcap Suitcase Packer
///
/// Encrypts a plaintext value using the TPM-backed Suitcase key and writes
/// it into the Suitcase section of a JSON config file.
///
/// Uses Snowcap.TCrypt (SuitcaseCrypt) for encryption.
/// The Suitcase key is obtained by decrypting the sealed credential via
/// systemd-creds (requires sudo).
/// </summary>
public class Program
{
    private const string DefaultCredPath = "/etc/credstore.encrypted/suitcase-key.cred";
    private const string DefaultCredName = "suitcase-key";
    private const string SuitcaseSectionName = "Suitcase";

    public static int Main(string[] args)
    {
        if (args.Length == 0 || args[0] is "--help" or "-h")
        {
            PrintUsage();
            return 0;
        }

        string? filePath = null;
        string? key = null;
        string? value = null;
        string credPath = DefaultCredPath;
        string credName = DefaultCredName;

        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--file" when i + 1 < args.Length:
                    filePath = args[++i];
                    break;
                case "--key" when i + 1 < args.Length:
                    key = args[++i];
                    break;
                case "--value" when i + 1 < args.Length:
                    value = args[++i];
                    break;
                case "--cred-path" when i + 1 < args.Length:
                    credPath = args[++i];
                    break;
                case "--cred-name" when i + 1 < args.Length:
                    credName = args[++i];
                    break;
                default:
                    Console.Error.WriteLine($"Unknown argument: {args[i]}");
                    PrintUsage();
                    return 1;
            }
        }

        if (filePath is null || key is null || value is null)
        {
            Console.Error.WriteLine("Error: --file, --key, and --value are all required.");
            PrintUsage();
            return 1;
        }

        if (!File.Exists(filePath))
        {
            Console.Error.WriteLine($"Error: Config file not found: {filePath}");
            return 1;
        }

        if (!File.Exists(credPath))
        {
            Console.Error.WriteLine($"Error: Sealed credential not found: {credPath}");
            Console.Error.WriteLine("Has the Suitcase key been sealed with systemd-creds?");
            return 1;
        }

        // Step 1: Get the decrypted Suitcase key from the TPM via systemd-creds
        byte[]? aesKey = DecryptCredential(credPath, credName);
        if (aesKey is null)
            return 1;

        if (aesKey.Length != 32)
        {
            Console.Error.WriteLine($"Error: Expected 32-byte AES-256 key, got {aesKey.Length} bytes.");
            return 1;
        }

        // Step 2: Encrypt the value using the shared library
        string encrypted = SuitcaseCrypt.Encrypt(value, aesKey);

        // Step 3: Update the JSON file
        if (!UpdateJsonFile(filePath, key, encrypted))
            return 1;

        Console.WriteLine($"Packed Suitcase.{key} in {filePath}");
        return 0;
    }

    /// <summary>
    /// Decrypts the sealed credential via systemd-creds to obtain the raw AES key.
    /// Requires sudo access.
    /// </summary>
    private static byte[]? DecryptCredential(string credPath, string credName)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "sudo",
            ArgumentList = {
                "systemd-creds", "decrypt",
                "--with-key=tpm2",
                "--tpm2-device=/dev/tpmrm0",
                $"--name={credName}",
                credPath, "-"
            },
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };

        try
        {
            using var process = Process.Start(psi);
            if (process is null)
            {
                Console.Error.WriteLine("Error: Failed to start systemd-creds.");
                return null;
            }

            using var ms = new MemoryStream();
            process.StandardOutput.BaseStream.CopyTo(ms);
            string stderr = process.StandardError.ReadToEnd();
            process.WaitForExit();

            if (process.ExitCode != 0)
            {
                Console.Error.WriteLine($"Error: systemd-creds decrypt failed (exit {process.ExitCode}).");
                if (!string.IsNullOrWhiteSpace(stderr))
                    Console.Error.WriteLine(stderr.Trim());
                return null;
            }

            return ms.ToArray();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error running systemd-creds: {ex.Message}");
            return null;
        }
    }

    /// <summary>
    /// Updates a single key in the Suitcase section of a JSON config file.
    /// Preserves all other content.
    /// </summary>
    private static bool UpdateJsonFile(string filePath, string key, string encryptedValue)
    {
        string json;
        try
        {
            json = File.ReadAllText(filePath);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error reading {filePath}: {ex.Message}");
            return false;
        }

        JsonNode? root;
        try
        {
            root = JsonNode.Parse(json, documentOptions: new JsonDocumentOptions
            {
                CommentHandling = JsonCommentHandling.Skip,
                AllowTrailingCommas = true
            });
        }
        catch (JsonException ex)
        {
            Console.Error.WriteLine($"Error parsing JSON: {ex.Message}");
            return false;
        }

        if (root is not JsonObject rootObj)
        {
            Console.Error.WriteLine("Error: Config file root is not a JSON object.");
            return false;
        }

        if (!rootObj.ContainsKey(SuitcaseSectionName))
        {
            Console.Error.WriteLine($"Error: No \"{SuitcaseSectionName}\" section found in {filePath}.");
            Console.Error.WriteLine("Create the Suitcase section in the config file first.");
            return false;
        }

        if (rootObj[SuitcaseSectionName] is not JsonObject suitcase)
        {
            Console.Error.WriteLine($"Error: \"{SuitcaseSectionName}\" is not a JSON object.");
            return false;
        }

        if (!suitcase.ContainsKey(key))
        {
            Console.Error.WriteLine($"Error: Key \"{key}\" not found in Suitcase section.");
            Console.Error.WriteLine($"Available keys: {string.Join(", ", suitcase.Select(kv => kv.Key))}");
            return false;
        }

        suitcase[key] = encryptedValue;

        var writeOptions = new JsonSerializerOptions
        {
            WriteIndented = true,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        };

        try
        {
            string updated = rootObj.ToJsonString(writeOptions);
            File.WriteAllText(filePath, updated + Environment.NewLine);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error writing {filePath}: {ex.Message}");
            return false;
        }

        return true;
    }

    private static void PrintUsage()
    {
        Console.WriteLine("""
            tcrypt-pack — Snowcap Suitcase Packer

            Encrypts a value and writes it into the Suitcase section of a JSON config file.
            Uses the TPM-backed Suitcase key via systemd-creds (requires sudo).

            Usage:
              tcrypt-pack --file <config.json> --key <name> --value <plaintext>

            Required:
              --file       Path to the JSON config file (must have a Suitcase section)
              --key        Key name within the Suitcase section to update
              --value      Plaintext value to encrypt and store

            Optional:
              --cred-path  Path to sealed credential (default: /etc/credstore.encrypted/suitcase-key.cred)
              --cred-name  Credential name embedded in .cred file (default: suitcase-key)
              --help       Show this help

            Example:
              sudo tcrypt-pack --file /opt/myapp/appsettings.json --key DbConnection \
                --value "Server=db.local;Database=mydb;User=app;Password=secret"

            Encryption: AES-256-GCM (authenticated encryption).
            Format: Base64(nonce[12] + ciphertext + tag[16])
            """);
    }
}
