using System;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

class Program
{
    static async Task Main()
    {
        var publicKey = "myPublicKey";
        var secretKey = "mySecretKey12345";
        var apiUrl = "http://localhost:5000/api/test/hello"; // adjust if needed

        var method = "GET";
        var uri = new Uri(apiUrl);
        var path = uri.AbsolutePath;
        var date = DateTime.UtcNow.ToString("r"); // RFC1123

        // Payload = METHOD + PATH + DATE
        var payload = $"{method}\n{path}\n{date}";
        var signature = ComputeSignature(payload, secretKey);

        using var client = new HttpClient();
        var request = new HttpRequestMessage(HttpMethod.Get, apiUrl);

        request.Headers.Add("x-date", date);
        request.Headers.Add("Authorization", $"HMAC {publicKey}:{signature}");

        var response = await client.SendAsync(request);
        var responseText = await response.Content.ReadAsStringAsync();

        Console.WriteLine($"Response: {response.StatusCode}");
        Console.WriteLine(responseText);
    }

    static string ComputeSignature(string data, string secret)
    {
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
        var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
        return Convert.ToBase64String(hash);
    }
}
