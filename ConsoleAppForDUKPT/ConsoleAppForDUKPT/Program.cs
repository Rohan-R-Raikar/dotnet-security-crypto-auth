using System;
using System.Linq;
using System.Security.Cryptography;

public static class DUKPT
{
    public static string DerivePreferredPek(string ipekHex, string ksnHex)
    {
        byte[] K = HexToBytes(ipekHex);
        if (K.Length != 16) throw new ArgumentException("IPEK must be 16 bytes (32 hex chars)");

        byte[] ksn = HexToBytes(ksnHex);
        if (ksn.Length != 10) throw new ArgumentException("KSN must be 10 bytes (20 hex chars)");

        ulong R = BytesToUlongBE(ksn, 2);

        const ulong BASE_MASK = 0xFFFFFFFFFFE00000UL;
        const ulong CTR_MASK = 0x00000000001FFFFFUL;

        ulong Rreg = R & BASE_MASK;
        ulong C = R & CTR_MASK;

        byte[] MK = HexToBytes("C0C0C0C000000000C0C0C0C000000000");

        for (int i = 20; i >= 0; i--)
        {
            ulong bit = 1UL << i;
            if ((C & bit) == 0) continue;

            ulong rWithBit = Rreg | bit;
            byte[] R8 = UlongTo8BytesBE(rWithBit);

            byte[] left = Ereg(Xor16(K, MK), R8);

            byte[] right = Ereg(K, R8);

            K = left.Concat(right).ToArray();

            Rreg = rWithBit;
        }

        return BytesToHex(K);
    }

    private static byte[] Ereg(byte[] K16, byte[] R8)
    {
        byte[] KL = K16.Take(8).ToArray();
        byte[] KR = K16.Skip(8).Take(8).ToArray();

        byte[] input = Xor8(KR, R8);

        byte[] cipher = DesCbcEncryptOneBlockNoPad(KL, input);

        byte[] result = Xor8(KR, cipher);
        return result;
    }

    private static byte[] DesCbcEncryptOneBlockNoPad(byte[] key8, byte[] block8)
    {
        using var des = DES.Create();
        des.Mode = CipherMode.CBC;
        des.Padding = PaddingMode.None;
        des.Key = key8;
        des.IV = new byte[8];
        using var enc = des.CreateEncryptor();
        var result = enc.TransformFinalBlock(block8, 0, 8);
        return result;
    }

    private static byte[] HexToBytes(string hex)
    {
        if (hex.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) hex = hex[2..];
        if (hex.Length % 2 != 0) throw new ArgumentException("Hex length must be even");
        var bytes = new byte[hex.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        }
        return bytes;
    }

    private static string BytesToHex(byte[] bytes) => string.Concat(bytes.Select(b => b.ToString("X2")));

    private static byte[] Xor8(byte[] a, byte[] b)
    {
        var r = new byte[8];
        for (int i = 0; i < 8; i++) r[i] = (byte)(a[i] ^ b[i]);
        return r;
    }

    private static byte[] Xor16(byte[] a, byte[] b)
    {
        var r = new byte[16];
        for (int i = 0; i < 16; i++) r[i] = (byte)(a[i] ^ b[i]);
        return r;
    }

    private static ulong BytesToUlongBE(byte[] bytes, int offset)
    {
        ulong v = 0;
        for (int i = 0; i < 8; i++) v = (v << 8) | bytes[offset + i];
        return v;
    }

    private static byte[] UlongTo8BytesBE(ulong v)
    {
        var b = new byte[8];
        for (int i = 7; i >= 0; i--) { b[i] = (byte)(v & 0xFF); v >>= 8; }
        return b;
    }


}

public class Program
{
    public static void Main()
    {
        Console.Write("Enter IPEK (32 hex chars): ");
        string ipek = Console.ReadLine()?.Trim() ?? "";

        Console.Write("Enter KSN (20 hex chars): ");
        string ksn = Console.ReadLine()?.Trim() ?? "";

        string pek = DUKPT.DerivePreferredPek(ipek, ksn);
        Console.WriteLine($"\n=== FINAL OUTPUT ===\nPEK = {pek}");

    }
}
