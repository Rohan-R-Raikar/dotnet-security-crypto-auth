using System;

namespace AesEncryptionDemo
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("=== == = AES Encryption / Decryption Demo = == ===\n");
            Console.WriteLine("Choose an option:");
            Console.WriteLine("1. Encrypt");
            Console.WriteLine("2. Decrypt");
            Console.WriteLine("Enter choice (1 or 2): ");
            string choice = Console.ReadLine();

            if (choice == "1")
            {
                Console.WriteLine("\nEnter text to encrypt: ");
                string plainText = Console.ReadLine();
                Console.WriteLine("\nEnter text to Secrete Key: ");
                string keyHere = Console.ReadLine();

                string encrypted = AesEncryptionHelper.Encrypt(plainText,keyHere);
                Console.WriteLine($"\nEncrypted Text: {encrypted}");
            }
            else if (choice == "2")
            {
                Console.WriteLine("\nEnter encrypted text (Base64): ");
                string cipherText = Console.ReadLine();
                Console.WriteLine("\nEnter text to Secrete Key: ");
                string keyHere = Console.ReadLine();

                try
                {
                    string decrypted = AesEncryptionHelper.Decrypt(cipherText,keyHere);
                    Console.WriteLine($"\nDecrypted Text: {decrypted}");
                }
                catch
                {
                    Console.WriteLine("\nError: Could not decrypt. Please check your input.");
                }
            }
            else
            {
                Console.WriteLine("\nInvalid choice!");
            }

            Console.WriteLine("\nPress any key to exit...");
            Console.ReadKey();
        }
    }
}


/*
Choose an option:
1. Encrypt
2. Decrypt

=== == = AES Encryption Demo = == ===
Enter choice (1 or 2): 1
Enter text to encrypt:
Encrypted Text:

=== == = AES Decryption Demo = == ===
Enter choice (1 or 2): 2
Enter encrypted text (Base64):
Decrypted Text:
*/