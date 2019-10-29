using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using NSec.Cryptography;
using System.Threading.Tasks;
using System.Text.Json;
using System.IO;
using System.Text;

namespace GmodNET.ModuleSigner
{
    class Program
    {
        struct TextKeyPair
        {
            public string PrivateKey {get; set;}
            public string PublicKey {get; set;}
        }
        struct ModuleSignature
        {
            public string Version {get; set;}
            public string Signature {get; set;}
        }

        static void Main(string[] args)
        {
            Regex sign_matcher = new Regex(@"--sign=.*", RegexOptions.Compiled | RegexOptions.ECMAScript);
            Regex key_matcher = new Regex(@"--key=.*", RegexOptions.Compiled | RegexOptions.ECMAScript);
            Regex version_matcher = new Regex(@"--version=.*", RegexOptions.Compiled | RegexOptions.ECMAScript);
            Regex verify_matcher = new Regex(@"--verify=.*", RegexOptions.Compiled | RegexOptions.ECMAScript);
            Regex signature_matcher = new Regex(@"--signature=.*", RegexOptions.Compiled | RegexOptions.ECMAScript);

            if (args.Any(s => s == "--help"))
            {
                string executable_name = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) switch
                {
                    true => "gms.exe",
                    _ => "./gms"
                };
                Console.WriteLine("GmodNetModuleSigner 1.0.0 by Gleb Krasilich. https://github.com/GlebChili/GmodNetModuleSigner.");
                Console.WriteLine("Usage: " + executable_name + " [FLAG1] [FLAG2] ...\n");
                Console.WriteLine("Flags:\n");
                Console.WriteLine("--help: usage help\n");
                Console.WriteLine("--generate-key: Generate new private and public keys pair and save it as private.modulekey file.\n");
                Console.WriteLine("--sign=[module_to_sign_path]: sign given file (relative or absolute path). Must be used wtih --key flag " +
                    "and --version flag. Output: signature.modulesign file.\n");
                Console.WriteLine("--key=[path_to_key]: Use following key for sign and verification process (relative or absolute path).\n");
                Console.WriteLine("--version=[module_version]: Explicitly specify module version to add to *.modulekey file.\n");
                Console.WriteLine("--verify=[module_to_verify_path]: Verify signature of the module. Must be used with --key and --signature flags.");
                Console.WriteLine("--signature=[path_to_the_signature_file]: Signature for the verification process.");
            }
            else if (args.Any(s => s == "--generate-key"))
            { 
                Console.WriteLine("Generating new key pair");

                Task<TextKeyPair> future_key = Task<TextKeyPair>.Factory.StartNew(GenerateKey, TaskCreationOptions.LongRunning);

                int tick_counter = 0;

                while(!future_key.IsCompleted)
                {
                    tick_counter++;
                    tick_counter = tick_counter % 1000000000;

                    if(tick_counter == 0)
                    {
                        Console.Write(".");
                    }
                }

                Console.Write("\n");

                TextKeyPair result = future_key.Result;

                byte[] key_json = JsonSerializer.SerializeToUtf8Bytes<TextKeyPair>(result, new JsonSerializerOptions { WriteIndented = true });

                File.WriteAllBytes("private.modulekey", key_json);

                Console.WriteLine("Key pair generated and saved as private.modulekey file. KEEP YOUR SECRET KEY SAFE!");
            }
            else if(args.Any(s => sign_matcher.IsMatch(s)))
            {
                Console.WriteLine("Starting sign process...");

                string sign_flag = args.First(s => sign_matcher.IsMatch(s));
                string sign_path;

                try
                {
                    sign_path = sign_flag.Split("=")[1];
                }
                catch
                {
                    Console.WriteLine("Path for file to sign is empty or invalid. Try again.");
                    return;
                }

                string key_flag = args.First(s => key_matcher.IsMatch(s));
                string key_path;
                if(key_flag == null || key_flag == String.Empty)
                {
                    Console.WriteLine("The --key=[path_to_key] flag is missing. Try again.");
                    return;
                }

                try
                {
                    key_path = key_flag.Split("=")[1];
                }
                catch
                {
                    Console.WriteLine("Key file path is empty or invalid. Try again.");
                    return;
                }

                byte[] key_blob;
                try
                {
                    key_blob = File.ReadAllBytes(key_path);
                }
                catch(Exception e)
                {
                    Console.WriteLine("Unable to read key file: " + e.GetType().ToString() + " " + e.Message +". Try again.");
                    return;
                }

                TextKeyPair key_pair;
                try
                {
                    key_pair = JsonSerializer.Deserialize<TextKeyPair>(key_blob);
                }
                catch (Exception e)
                { 
                    Console.WriteLine("Unable to parse key file: " + e.GetType().ToString() + " " + e.Message + ". Try again.");
                    return;
                }

                if(key_pair.PrivateKey == null || key_pair.PrivateKey == String.Empty)
                {
                    Console.WriteLine("The key file contains no secret key. Try again.");
                    return;
                }

                string version_flag = args.First(s => version_matcher.IsMatch(s));
                if (version_flag == null || version_flag == String.Empty)
                { 
                    Console.WriteLine("--version flag is missing. Try again.");
                    return;
                }

                string version_name;
                try
                {
                    version_name = version_flag.Split("=")[1];
                }
                catch
                {
                    Console.WriteLine("The vesrsion is empty or invalid. Try again.");
                    return;
                }

                Sha512 sha512 = HashAlgorithm.Sha512;

                byte[] file_blob;
                try
                {
                    file_blob = File.ReadAllBytes(sign_path);
                }
                catch(Exception e)
                {
                    Console.WriteLine("Unable to read file to sign: " + e.GetType().ToString() + " " + e.Message + ". Try again.");
                    return;
                }

                byte[] file_hash = sha512.Hash(file_blob);

                file_hash = file_hash.Concat(Encoding.UTF8.GetBytes(version_name)).ToArray();

                byte[] final_hash = sha512.Hash(file_hash);

                byte[] raw_private_key = HexToBytes(key_pair.PrivateKey);

                Ed25519 ed25519 = SignatureAlgorithm.Ed25519;

                Key private_key;

                try
                {
                    private_key = Key.Import(ed25519, raw_private_key, KeyBlobFormat.RawPrivateKey);
                }
                catch(Exception e)
                {
                    Console.WriteLine("Unable to import private key: " + e.GetType() + " " + e.Message + ". Try again.");
                    return;
                }

                byte[] final_signature = ed25519.Sign(private_key, final_hash);

                ModuleSignature sign_struct = new ModuleSignature
                {
                    Version = version_name,
                    Signature = BitConverter.ToString(final_signature).Replace("-", "")
                };

                byte[] sign_to_write = JsonSerializer.SerializeToUtf8Bytes<ModuleSignature>(sign_struct, new JsonSerializerOptions{WriteIndented = true});

                File.WriteAllBytes("signature.modulesign", sign_to_write);

                Console.WriteLine("File was successfully signed.");
            }
            else if(args.Any(s => verify_matcher.IsMatch(s)))
            {
                Console.WriteLine("Starting verification process...");

                string verify_flag = args.First(s => verify_matcher.IsMatch(s));
                
                string verify_path;
                try
                {
                    verify_path = verify_flag.Split("=")[1];
                }
                catch
                {
                    Console.WriteLine("Path for the file to verify is empty or invalid. Try again.");
                    return;
                }

                string key_flag = args.First(s => key_matcher.IsMatch(s));
                string key_path;
                if(key_flag == null || key_flag == String.Empty)
                {
                    Console.WriteLine("The --key=[path_to_key] flag is missing. Try again.");
                    return;
                }

                try
                {
                    key_path = key_flag.Split("=")[1];
                }
                catch
                {
                    Console.WriteLine("Key file path is empty or invalid. Try again.");
                    return;
                }

                string signature_flag = args.First(s => signature_matcher.IsMatch(s));
                string signature_path;
                if(signature_flag == null || signature_flag == String.Empty)
                {
                    Console.WriteLine("-signature=[path_to_the_signature] flag is missing. Try again.");
                    return;
                }
                try
                {
                    signature_path = signature_flag.Split("=")[1];
                }
                catch
                {
                    Console.WriteLine("Signature path is empty or invalid. Try again.");
                    return;
                }

                byte[] file_blob;
                try
                { 
                    file_blob = File.ReadAllBytes(verify_path);
                }
                catch(Exception e)
                {
                    Console.WriteLine("Unable to read the module to verify: " + e.GetType().ToString() + " " + e.Message + ". Try again.");
                    return;
                }

                byte[] key_blob;
                try
                {
                    key_blob = File.ReadAllBytes(key_path);
                }
                catch(Exception e)
                {
                    Console.WriteLine("Unable to read key: " + e.GetType().ToString() + " " + e.Message + ". Try again.");
                    return;
                }

                byte[] signature_blob;
                try
                {
                    signature_blob = File.ReadAllBytes(signature_path);
                }
                catch(Exception e)
                {
                    Console.WriteLine("Unable to read signature: " + e.GetType() + " " + e.Message + ". Try again.");
                    return;
                }

                TextKeyPair key_pair;
                try
                {
                    key_pair = JsonSerializer.Deserialize<TextKeyPair>(key_blob);
                }
                catch(Exception e)
                {
                    Console.WriteLine("Unable to parse key file: " + e.GetType().ToString() + " " + e.Message + ". Try again.");
                    return;
                }

                if(key_pair.PublicKey == null || key_pair.PublicKey == String.Empty)
                {
                    Console.WriteLine("Public key is empty or invalid. Try again.");
                    return;
                }

                ModuleSignature signature;
                try
                {
                    signature = JsonSerializer.Deserialize<ModuleSignature>(signature_blob);
                }
                catch(Exception e)
                {
                    Console.WriteLine("Unable to parse signature file: " + e.GetType().ToString() + e.Message + ". Try again.");
                    return;
                }

                Sha512 sha512 = HashAlgorithm.Sha512;

                byte[] file_hash = sha512.Hash(file_blob);

                file_hash = file_hash.Concat(Encoding.UTF8.GetBytes(signature.Version)).ToArray();

                byte[] final_hash = sha512.Hash(file_hash);

                Ed25519 ed25519 = SignatureAlgorithm.Ed25519;

                PublicKey public_key;
                try
                {
                    byte[] raw_public_key = HexToBytes(key_pair.PublicKey);
                    public_key = PublicKey.Import(ed25519, raw_public_key, KeyBlobFormat.RawPublicKey);
                }
                catch(Exception e)
                {
                    Console.WriteLine("Unable to parse public key: " + e.GetType().ToString() + " " + e.Message + ". Try again.");
                    return;
                }

                try
                {
                    bool is_valid = ed25519.Verify(public_key, final_hash, HexToBytes(signature.Signature));
                    if (is_valid)
                    {
                        Console.WriteLine("Signature is valid.");
                    }
                    else
                    { 
                        Console.WriteLine("Signature is NOT valid.");
                    }
                }
                catch(Exception e)
                {
                    Console.WriteLine("Unable to verify signature: " + e.GetType().ToString() + " " + e.Message + ". Try again.");
                    return;
                }
            }
            else
            {
                Console.WriteLine("GmodNetModuleSigner 1.0.0 by Gleb Krasilich. https://github.com/GlebChili/GmodNetModuleSigner.");
                Console.WriteLine("Use --help flag for usage help.");
            }
        }

        static TextKeyPair GenerateKey()
        {
            var ed25519 = SignatureAlgorithm.Ed25519;

            var key = Key.Create(ed25519, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport});

            var public_key = key.PublicKey;

            byte[] key_blob = key.Export(KeyBlobFormat.RawPrivateKey);

            byte[] public_key_blob = public_key.Export(KeyBlobFormat.RawPublicKey);

            return new TextKeyPair
            {
                PrivateKey = BitConverter.ToString(key_blob).Replace("-", ""),
                PublicKey = BitConverter.ToString(public_key_blob).Replace("-", "")
            };
        }

        static byte[] HexToBytes(string hex_string)
        {
            if(hex_string.Length % 2 != 0)
            {
                throw new ArgumentException("hex_string has odd length.");
            }

            byte[] res = new byte[hex_string.Length / 2];

            for(int i = 0; i < hex_string.Length; i += 2)
            {
                res[i/2] = Convert.ToByte(hex_string.Substring(i, 2), 16);
            }

            return res;
        }
    }
}
