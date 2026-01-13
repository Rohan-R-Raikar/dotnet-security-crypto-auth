using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Globalization;

namespace TR31VersionD_SpecKDF_Fixed
{
    class Program
    {
        static void Main()
        {
            Console.WriteLine("TR-31 Version D Utility (Spec-style CMAC KDF) — Fixed parsing");
            Console.WriteLine("1 = Encrypt (Build TR-31 Block)");
            Console.WriteLine("2 = Decrypt (Extract Plain Key)");
            Console.Write("Choose option: ");
            string choice = Console.ReadLine()?.Trim();

            if (choice == "1")
            {
                Console.Write("Enter KBPK (hex, 16 bytes): ");
                string kbpkHex = Console.ReadLine().Trim();

                Console.Write("Enter Plain Key (hex): ");
                string plainKeyHex = Console.ReadLine().Trim();

                Console.Write("Enter Header (with D0000 as placeholder length): ");
                string header = Console.ReadLine().Trim();

                Console.Write("Use random padding? (y/n) [y]: ");
                string padChoice = Console.ReadLine()?.Trim().ToLower();
                bool useRandom = string.IsNullOrEmpty(padChoice) || padChoice == "y" || padChoice == "yes";

                string block = TR31.BuildTr31Block(header, kbpkHex, plainKeyHex, useRandomPadding: useRandom);
                Console.WriteLine("\nGenerated TR-31 Block:");
                Console.WriteLine(block);
            }
            else if (choice == "2")
            {
                Console.Write("Enter KBPK (hex, 16 bytes): ");
                string kbpkHex = Console.ReadLine().Trim();

                Console.Write("Enter TR-31 Block: ");
                string block = Console.ReadLine().Trim();

                try
                {
                    string plainKey = TR31.DecryptTr31Block(block, kbpkHex);
                    Console.WriteLine("\nRecovered Plain Key:");
                    Console.WriteLine(plainKey);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"\nERROR: {ex.GetType().Name}: {ex.Message}");
                }
            }
            else
            {
                Console.WriteLine("Invalid choice.");
            }
        }
    }

    public static class TR31
    {
        public static string BuildTr31Block(string headerWithPlaceholder, string kbpkHex, string clearKeyHex, bool useRandomPadding = true)
        {
            if (string.IsNullOrWhiteSpace(headerWithPlaceholder)) throw new ArgumentNullException(nameof(headerWithPlaceholder));
            if (headerWithPlaceholder.Length < 16) throw new ArgumentException("Header is too short (must contain at least 16 chars fixed header).");
            if (headerWithPlaceholder[0] != 'D') throw new ArgumentException("Only Version 'D' supported (header must start with 'D').");

            byte[] KBPK = HexToBytes(kbpkHex);
            byte[] clearKey = HexToBytes(clearKeyHex);

            byte[] payload = BuildPayload(clearKey, useRandomPadding);

            int ciphertextHexLen = payload.Length * 2;

            int macHexLen = 16 * 2;
            
            int bodyHexLen = ciphertextHexLen + macHexLen;

            string headerPatched = PatchLength(headerWithPlaceholder, bodyHexLen);
            Console.WriteLine($"headerPatched {headerPatched}");

            byte[] KBEK = DeriveKey_Cmac(KBPK, "KBEK", Encoding.ASCII.GetBytes(headerPatched), 128);
            byte[] KBMK = DeriveKey_Cmac(KBPK, "KBMK", Encoding.ASCII.GetBytes(headerPatched), 128);

            Console.WriteLine($"KBEK = {BytesToHex(KBEK)}");
            Console.WriteLine($"KBMK = {BytesToHex(KBMK)}");

            byte[] ciphertext = AesCbcEncrypt(KBEK, new byte[16], payload);

            byte[] mac = AesCmac(KBMK, Concat(Encoding.ASCII.GetBytes(headerPatched), ciphertext));

            return headerPatched + BytesToHex(ciphertext) + BytesToHex(mac);
        }

        public static string DecryptTr31Block(string block, string kbpkHex)
        {
            if (string.IsNullOrWhiteSpace(block)) throw new ArgumentNullException(nameof(block));
            if (block[0] != 'D') throw new ArgumentException("Block does not start with Version 'D'");

            if (block.Length < 32 + 16) throw new ArgumentException("Block too short to contain MAC.");

            if (block.Length < 16) throw new ArgumentException("Block too short for TR-31 fixed header.");
            string fixedHeader = block.Substring(0, 16);

            int pos = 16;
            while (pos + 4 <= block.Length)
            {
                string maybeId = block.Substring(pos, 2);
                if (!IsAsciiUpperAlpha(maybeId[0]) || !IsAsciiUpperAlpha(maybeId[1]))
                {
                    break;
                }

                string lenHex = block.Substring(pos + 2, 2);
                if (!int.TryParse(lenHex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out int optLen))
                    throw new ArgumentException("Invalid optional block length (non-hex).");

                int dataStart = pos + 4;
                int dataEnd = dataStart + optLen;
                if (dataEnd > block.Length) throw new ArgumentException("Malformed optional block (data length exceeds block).");

                pos = dataEnd;
            }

            int headerEndIndex = pos;
            if (headerEndIndex >= block.Length - 32) throw new ArgumentException("No ciphertext found after header (block too short).");

            string macHex = block.Substring(block.Length - 32);
            string cipherHex = block.Substring(headerEndIndex, block.Length - headerEndIndex - 32);

            byte[] ciphertext = HexToBytes(cipherHex);
            byte[] mac = HexToBytes(macHex);
            byte[] KBPK = HexToBytes(kbpkHex);

            string headerAscii = block.Substring(0, headerEndIndex);
            byte[] headerBytes = Encoding.ASCII.GetBytes(headerAscii);

            byte[] KBEK = DeriveKey_Cmac(KBPK, "KBEK", headerBytes, 128);
            byte[] KBMK = DeriveKey_Cmac(KBPK, "KBMK", headerBytes, 128);

            Console.WriteLine($"KBEK = {BytesToHex(KBEK)}");
            Console.WriteLine($"KBMK = {BytesToHex(KBMK)}");

            byte[] expectedMac = AesCmac(KBMK, Concat(headerBytes, ciphertext));
            if (!mac.SequenceEqual(expectedMac))
            {
                throw new CryptographicException($"MAC verification failed! Provided={BytesToHex(mac)} Expected={BytesToHex(expectedMac)}");
            }

            byte[] plaintext = AesCbcDecrypt(KBEK, new byte[16], ciphertext);

            if (plaintext.Length < 2) throw new ArgumentException("Decrypted payload too short.");
            int keyLen = (plaintext[0] << 8) | plaintext[1];
            if (2 + keyLen > plaintext.Length) throw new ArgumentException("Decrypted payload missing key bytes.");

            byte[] key = new byte[keyLen];
            Array.Copy(plaintext, 2, key, 0, keyLen);

            return BytesToHex(key);
        }

        private static byte[] DeriveKey_Cmac(byte[] kbpk, string labelAscii, byte[] context, int bitLen)
        {
            if (bitLen % 8 != 0) throw new ArgumentException("bitLen must be multiple of 8");
            int keyBytes = bitLen / 8;
            byte[] result = new byte[0];
            int counter = 1;

            //Console.WriteLine(); // spacer
            //Console.WriteLine($"Deriving key (label='{labelAscii}', L={bitLen}) with context (ascii)='{(context == null ? "" : Encoding.ASCII.GetString(context))}'");

            while (result.Length < keyBytes)
            {
                byte[] counterBytes = BitConverter.GetBytes(System.Net.IPAddress.HostToNetworkOrder(counter)); // big-endian
                byte[] label = Encoding.ASCII.GetBytes(labelAscii);
                byte[] sep = new byte[] { 0x00 };
                byte[] L = BitConverter.GetBytes(System.Net.IPAddress.HostToNetworkOrder(bitLen)); // big-endian
                byte[] input = Concat(counterBytes, label, sep, context ?? Array.Empty<byte>(), L);

                //Console.WriteLine($"KDF input (counter={counter}): {BytesToHex(input)}");

                byte[] outBlock = AesCmac(kbpk, input);

                // show the resulting CMAC output used for this counter
                Console.WriteLine($"KDF outBlock (counter={counter}): {BytesToHex(outBlock)}");

                int need = Math.Min(outBlock.Length, keyBytes - result.Length);
                result = result.Concat(outBlock.Take(need)).ToArray();
                counter++;
            }

            Console.WriteLine($"Derived key ({labelAscii}) = {BytesToHex(result.Take(keyBytes).ToArray())}");
            Console.WriteLine();

            return result.Take(keyBytes).ToArray();
        }

        private static byte[] AesCmac(byte[] key, byte[] data)
        {
            byte[] zero = new byte[16];
            byte[] L = AesEcbEncryptOneBlock(key, zero);
            byte[] K1 = LeftShiftOneBit(L);
            if ((L[0] & 0x80) != 0) K1[15] ^= 0x87;
            byte[] K2 = LeftShiftOneBit(K1);
            if ((K1[0] & 0x80) != 0) K2[15] ^= 0x87;

            int n = (data.Length + 15) / 16;
            if (n == 0) n = 1;
            byte[][] M = new byte[n][];
            for (int i = 0; i < n; i++)
            {
                M[i] = new byte[16];
                int copy = Math.Min(16, data.Length - i * 16);
                if (copy > 0) Array.Copy(data, i * 16, M[i], 0, copy);
            }

            bool lastComplete = (data.Length != 0) && (data.Length % 16 == 0);
            if (lastComplete) XorInPlace(M[n - 1], K1);
            else
            {
                int rem = data.Length % 16;
                M[n - 1][rem] = 0x80;
                XorInPlace(M[n - 1], K2);
            }

            byte[] X = new byte[16];
            for (int i = 0; i < n - 1; i++)
            {
                XorInPlace(X, M[i]);
                X = AesEcbEncryptOneBlock(key, X);
            }
            XorInPlace(X, M[n - 1]);
            X = AesEcbEncryptOneBlock(key, X);

            //Console.WriteLine($"CMAC Subkeys:");
            //Console.WriteLine($"  L   = {BytesToHex(L)}");
            //Console.WriteLine($"  K1  = {BytesToHex(K1)}");
            //Console.WriteLine($"  K2  = {BytesToHex(K2)}");

            return X;
        }

        private static byte[] AesEcbEncryptOneBlock(byte[] key, byte[] block16)
        {
            using var aes = Aes.Create();
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;
            aes.Key = key;
            using var enc = aes.CreateEncryptor();
            return enc.TransformFinalBlock(block16, 0, 16);
        }

        private static byte[] AesCbcEncrypt(byte[] key, byte[] iv, byte[] pt)
        {
            using var aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.None;
            aes.Key = key;
            aes.IV = iv;
            using var enc = aes.CreateEncryptor();
            return enc.TransformFinalBlock(pt, 0, pt.Length);
        }

        private static byte[] AesCbcDecrypt(byte[] key, byte[] iv, byte[] ct)
        {
            using var aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.None;
            aes.Key = key;
            aes.IV = iv;
            using var dec = aes.CreateDecryptor();
            return dec.TransformFinalBlock(ct, 0, ct.Length);
        }

        private static byte[] BuildPayload(byte[] key, bool useRandomPadding)
        {
            if (key.Length > ushort.MaxValue) throw new ArgumentException("Key too large");
            ushort len = (ushort)key.Length;
            byte[] lenBytes = new byte[] { (byte)(len >> 8), (byte)(len & 0xFF) };
            int total = 2 + key.Length;
            int pad = (16 - (total % 16)) % 16;
            byte[] padding = new byte[pad];
            if (useRandomPadding && pad > 0) RandomNumberGenerator.Fill(padding);
            return Concat(lenBytes, key, padding);
        }

        private static string PatchLength(string headerWithPlaceholder, int bodyHexLength)
        {
            Console.WriteLine($"headerWithPlaceholder = {headerWithPlaceholder}");
            int afterVersionHeaderChars = headerWithPlaceholder.Length - 1;
            Console.WriteLine($"afterVersionHeaderChars = {afterVersionHeaderChars}");
            int totalAfterVersion = afterVersionHeaderChars + bodyHexLength;
            Console.WriteLine($"totalAfterVersion = {totalAfterVersion}");
            string len4 = totalAfterVersion.ToString("D4");
            Console.WriteLine($"len4 = {len4}");
            return headerWithPlaceholder.Substring(0, 1) + len4 + headerWithPlaceholder.Substring(5);
        }

        private static byte[] Concat(params byte[][] arrays)
        {
            int total = arrays.Sum(a => a.Length);
            byte[] r = new byte[total];
            int offset = 0;
            foreach (var a in arrays) { Buffer.BlockCopy(a, 0, r, offset, a.Length); offset += a.Length; }
            return r;
        }

        private static void XorInPlace(byte[] a, byte[] b) { for (int i = 0; i < a.Length; i++) a[i] ^= b[i]; }

        private static byte[] LeftShiftOneBit(byte[] input)
        {
            byte[] output = new byte[input.Length];
            int carry = 0;
            for (int i = input.Length - 1; i >= 0; i--)
            {
                int v = (input[i] << 1) | carry;
                output[i] = (byte)(v & 0xFF);
                carry = (v >> 8) & 1;
            }
            return output;
        }

        private static bool IsAsciiUpperAlpha(char c) => (c >= 'A' && c <= 'Z');

        private static byte[] HexToBytes(string hex)
        {
            if (hex.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) hex = hex.Substring(2);
            if (hex.Length % 2 != 0) throw new ArgumentException("Hex length must be even.");
            return Enumerable.Range(0, hex.Length / 2).Select(i => Convert.ToByte(hex.Substring(2 * i, 2), 16)).ToArray();
        }

        private static string BytesToHex(byte[] b) => string.Concat(b.Select(x => x.ToString("X2")));
    }
}
