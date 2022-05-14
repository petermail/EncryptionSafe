using EncryptionSafe.Encryption;
using EncryptionTest;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EncryptionSafe
{
    public class Program
    {
        public static void Main(string[] args)
        {
            MainAsync(args).GetAwaiter().GetResult();
        }

        public static async Task MainAsync(string[] args)
        {
            Console.WriteLine("Hello, this is simple encryption application that ilustrates how to use the encryption classes.");
            string filename = "encrypt.json";
            var encrypted = await EncryptedDictionary.LoadOrCreate(filename);
            var fakeO = new FakeObject(encrypted);

            if (encrypted.EncryptionService.IsInitializationRunning)
            {
                Console.WriteLine("Initalization of encryption.");
                while (encrypted.EncryptionService.IsInitializationRunning)
                {
                    System.Threading.Thread.Sleep(1000);
                    Console.Write(".");
                }
                Console.WriteLine();
                Console.WriteLine("Initalization " + (encrypted.EncryptionService.IsInitializationRunning ? "is still running" : "finished"));
                Console.WriteLine("Write a password:");
                var password = Console.ReadLine();
                Console.WriteLine("We are decrypting your password. This will take one minute.");
                encrypted.DecryptKey(password);

                Console.WriteLine("Write a secret:");
                var secret = Console.ReadLine();
                fakeO.Dict["itemName"].Secret = secret;
                fakeO.Dict["itemNameCopy"].Secret = secret;

                encrypted.EncryptAll();
                encrypted.Save(filename);
            }
            else
            {
                try
                {
                    Console.WriteLine("Write a password:");
                    var password = Console.ReadLine();
                    Console.WriteLine("We are decrypting your password. This will take one minute.");
                    encrypted.DecryptKey(password); // Not needed because DecryptPart will do this
                    encrypted.DecryptPart();

                    Console.WriteLine("Your two secrets are:");
                    Console.WriteLine(fakeO.Dict["itemName"].Secret);
                    Console.WriteLine(fakeO.Dict["itemNameCopy"].Secret);
                } catch (Exception ex)
                {
                    Console.WriteLine("Error: Wrong password.");
                    Console.WriteLine("Write a password:");
                    var password = Console.ReadLine();
                    Console.WriteLine("We are decrypting your password. This will take one minute.");
                    encrypted.DecryptKey(password); // Not needed because DecryptPart will do this
                    encrypted.DecryptPart(password);

                    Console.WriteLine("Your two secrets are:");
                    Console.WriteLine(fakeO.Dict["itemName"].Secret);
                    Console.WriteLine(fakeO.Dict["itemNameCopy"].Secret);
                }

                Console.WriteLine("Delete encrypted file Y/N:");
                var yesNo = Console.ReadLine();
                if (yesNo.Contains("y") || yesNo.Contains("Y"))
                {
                    System.IO.File.Delete(filename);
                }
            }
            
            Console.WriteLine("Press enter to end.");
            Console.ReadLine();
        }
    }
}
