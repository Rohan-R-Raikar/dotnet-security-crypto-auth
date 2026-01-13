using System;
using System.Linq;
using System.Security.Cryptography;

public static class DUKPT
{
    public static string DerivePEK(string ipekHex, string ksnHex)
        => BytesToHex(DerivePekCore(HexToBytes(ipekHex), HexToBytes(ksnHex)));

    public static string DecryptTrack2(string encryptedHex, string pekHex)
    {
        byte[] ct = HexToBytes(encryptedHex);
        byte[] pek = HexToBytes(pekHex);

        byte[] variantMask = HexToBytes("0000000000FF00000000000000FF0000");
        byte[] key16 = Xor(pek, variantMask);

        byte[] wk16 = SelfEncryptHalvesUnder3DesEcb(key16);

        byte[] key24 = ExpandToTwoKey3Des(wk16);
        byte[] pt = TripleDesCbcDecrypt(key24, new byte[8], ct);

        return BytesToHex(pt);
    }

    private static byte[] DerivePekCore(byte[] ipek, byte[] ksn)
    {
        if (ipek.Length != 16) throw new ArgumentException("IPEK must be 16 bytes");
        if (ksn.Length != 10) throw new ArgumentException("KSN must be 10 bytes");

        ulong R = BytesToUlongBE(ksn, 2);
        const ulong BASE_MASK = 0xFFFFFFFFFFE00000UL;
        const ulong CTR_MASK = 0x00000000001FFFFFUL;

        ulong Rreg = R & BASE_MASK;
        ulong C = R & CTR_MASK;

        byte[] MK = HexToBytes("C0C0C0C000000000C0C0C0C000000000");
        byte[] K = (byte[])ipek.Clone();

        for (int i = 20; i >= 0; i--)
        {
            ulong bit = 1UL << i;
            if ((C & bit) == 0) continue;

            ulong rWithBit = Rreg | bit;
            byte[] R8 = UlongTo8BytesBE(rWithBit);

            byte[] left = Ereg(Xor(K, MK), R8);
            byte[] right = Ereg(K, R8);
            K = left.Concat(right).ToArray();

            Rreg = rWithBit;
        }
        return K;
    }

    private static byte[] Ereg(byte[] K16, byte[] R8)
    {
        byte[] KL = K16.Take(8).ToArray();
        byte[] KR = K16.Skip(8).Take(8).ToArray();
        byte[] input = Xor(KR, R8);
        byte[] cipher = DesCbcEncryptOneBlockNoPad(KL, input);
        return Xor(KR, cipher);
    }

    private static byte[] SelfEncryptHalvesUnder3DesEcb(byte[] key16)
    {
        byte[] key24 = ExpandToTwoKey3Des(key16);
        using var tdes = TripleDES.Create();
        tdes.Mode = CipherMode.ECB;
        tdes.Padding = PaddingMode.None;
        tdes.Key = key24;

        byte[] left = key16.Take(8).ToArray();
        byte[] right = key16.Skip(8).Take(8).ToArray();

        using var enc = tdes.CreateEncryptor();
        byte[] Lp = enc.TransformFinalBlock(left, 0, 8);
        byte[] Rp = enc.TransformFinalBlock(right, 0, 8);

        return Lp.Concat(Rp).ToArray();
    }

    private static byte[] TripleDesCbcDecrypt(byte[] key24, byte[] iv8, byte[] data)
    {
        using var tdes = TripleDES.Create();
        tdes.Mode = CipherMode.CBC;
        tdes.Padding = PaddingMode.None;
        tdes.Key = key24;
        tdes.IV = iv8;
        using var dec = tdes.CreateDecryptor();
        return dec.TransformFinalBlock(data, 0, data.Length);
    }

    private static byte[] ExpandToTwoKey3Des(byte[] key16)
        => key16.Concat(key16.Take(8)).ToArray();

    private static byte[] DesCbcEncryptOneBlockNoPad(byte[] key8, byte[] block8)
    {
        using var des = DES.Create();
        des.Mode = CipherMode.CBC;
        des.Padding = PaddingMode.None;
        des.Key = key8;
        des.IV = new byte[8];
        using var enc = des.CreateEncryptor();
        return enc.TransformFinalBlock(block8, 0, 8);
    }

    private static byte[] HexToBytes(string hex)
    {
        if (hex.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) hex = hex[2..];
        if (hex.Length % 2 != 0) throw new ArgumentException("Hex length must be even");
        var bytes = new byte[hex.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
            bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        return bytes;
    }

    private static string BytesToHex(byte[] bytes)
        => string.Concat(bytes.Select(b => b.ToString("X2")));

    private static byte[] Xor(byte[] a, byte[] b)
        => a.Zip(b, (x, y) => (byte)(x ^ y)).ToArray();

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
        string ipek = "406997FA1C2C4CBB02FEDDC9322C5DFF";
        string ksn = "FFFF0000000020400352";
        string ct = "54fffac25a2455f5eee27b72b8d9a08e75cefce58299ee71fbe000f98603ffca";

        string pek = DUKPT.DerivePEK(ipek, ksn);
        string pt = DUKPT.DecryptTrack2(ct, pek);

        Console.WriteLine($"PEK = {pek}");
        Console.WriteLine($"Decrypted Track2 = {pt}");
    }
}
