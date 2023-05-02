using System;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace CNGKey
{
    internal class Program
    {
        private const CngKeyCreationOptions UseArchivableKey = (CngKeyCreationOptions)0x00020000;

        static void Main(string[] args)
        {

            //Creates a key with a certificate 
            CreateKey();

            //Creates a key with the key name
            CreateKey("MySoftwareKey");

            Console.Read();
        }

        /// <summary>
        /// In CNG (Cryptography Next Generation), a machine key and an ephemeral key are two different types of keys used for different purposes.
        /// A machine key is a key that is associated with a specific computer or device, rather than with a particular user. 
        /// Machine keys are typically used for encryption and decryption operations that are performed by the computer or device itself, rather than by a specific user.
        /// Ephemeral keys, on the other hand, are keys that are created and used only for a short period of time, usually during a single cryptographic operation. 
        /// Ephemeral keys are typically used for key exchange or key agreement protocols, where two parties need to establish a shared secret key.
        /// </summary>
        private static void CreateKey(string keyName)
        {
            Console.WriteLine("-----------------------------------------------------------------------");
            Console.WriteLine("Creating a key with just a Key name");

            try
            {
                // Create CngKeyCreationParameters
                var keyParams = new CngKeyCreationParameters
                {
                    KeyUsage = CngKeyUsages.Signing,
                    Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider,
                
                    //Machine keys are stored in the machine-level key store and are accessible to all users who have the appropriate permissions.
                    //This means that any user on the computer can access and use the machine key.
                    KeyCreationOptions = CngKeyCreationOptions.MachineKey | CngKeyCreationOptions.OverwriteExistingKey,

                    ExportPolicy = CngExportPolicies.None,
                };

                // Create the key
                using (var key = CngKey.Create(CngAlgorithm.Rsa, keyName, keyParams))
                {
                    PrintKeyProps(key);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                Console.WriteLine();
            }

            Console.WriteLine("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
        }

        /// <summary>
        /// In CNG (Cryptography Next Generation), a machine key and an ephemeral key are two different types of keys used for different purposes.
        /// A machine key is a key that is associated with a specific computer or device, rather than with a particular user. 
        /// Machine keys are typically used for encryption and decryption operations that are performed by the computer or device itself, rather than by a specific user.
        /// Ephemeral keys, on the other hand, are keys that are created and used only for a short period of time, usually during a single cryptographic operation. 
        /// Ephemeral keys are typically used for key exchange or key agreement protocols, where two parties need to establish a shared secret key.
        /// </summary>
        private static void CreateKey()
        {
            const string keyName = "MyNewCertificateKey";

            Console.WriteLine("-----------------------------------------------------------------------");
            Console.WriteLine("Creating a key with ECDiffieHellmanCng SHA256 Key.");


            try
            {
                //Using Elliptic-curve Diffie–Hellman Key Agreement Protocol 
                var ecdh = new ECDiffieHellmanCng(CngKey.Create(CngAlgorithm.ECDiffieHellmanP256, null, new CngKeyCreationParameters { ExportPolicy = CngExportPolicies.AllowPlaintextExport }));

                //Export the keys
                var privateKey = ecdh.Key.Export(CngKeyBlobFormat.EccPrivateBlob);

                // Create CngKeyCreationParameters
                var keyParams = new CngKeyCreationParameters
                {
                    KeyUsage = CngKeyUsages.AllUsages,
                    Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider,

                    //Machine keys are stored in the machine-level key store and are accessible to all users who have the appropriate permissions.
                    //This means that any user on the computer can access and use the machine key.
                    KeyCreationOptions = CngKeyCreationOptions.MachineKey | CngKeyCreationOptions.OverwriteExistingKey,

                    ExportPolicy = CngExportPolicies.AllowPlaintextExport,

                    UIPolicy = new CngUIPolicy(CngUIProtectionLevels.None),

                    Parameters =
                    {
                        new CngProperty(CngKeyBlobFormat.GenericPrivateBlob.Format, privateKey, CngPropertyOptions.None)
                    }
                };

                // Create the key
                using (var key = CngKey.Create(CngAlgorithm.ECDiffieHellmanP256, keyName, keyParams))
                {

                    try
                    {
                        var exportedPrivateKey = key.Export(CngKeyBlobFormat.EccPrivateBlob);

                        //Compare the private keys 

                        if(ByteArrayAreTheSame(privateKey, exportedPrivateKey))
                            Console.WriteLine("generated private key and exported private key are the same!!!");
                        else
                            Console.WriteLine("generated private key and exported private key are DIFFERENT!!!");
                    }
                    catch(Exception ex)
                    {
                        Console.WriteLine($"Export of Private Key Failed during ECDiffieHellmanP256 Key Operation : { ex.Message }");
                    }
                    PrintKeyProps(key);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                Console.WriteLine();
            }

            Console.WriteLine("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
        }

        private static void PrintKeyProps(CngKey key)
        {
            Console.WriteLine($"Key UniqueName'{key.UniqueName}' created successfully.");
            Console.WriteLine($"Key Name'{key.KeyName}' created successfully.");
            Console.WriteLine($"Is Machine Key ? {key.IsMachineKey} ");
            Console.WriteLine($"Is Ephemeral Key ? {key.IsEphemeral} ");
        }

        // byte[] is implicitly convertible to ReadOnlySpan<byte>
        static bool ByteArrayAreTheSame(ReadOnlySpan<byte> a1, ReadOnlySpan<byte> a2)
        {
            return a1.SequenceEqual(a2);
        }
    }
}