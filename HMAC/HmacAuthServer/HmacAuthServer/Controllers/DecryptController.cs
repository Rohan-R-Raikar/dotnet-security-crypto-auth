using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using System.Security.Cryptography;
using System.Text;
using HmacAuthServer.Models;

namespace HmacAuthServer.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class DecryptController : ControllerBase
    {
        private readonly IConfiguration _configuration;

        public DecryptController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        //[HttpPost("decrypt")]
        //public IActionResult Decrypt([FromBody] DecryptRequest request)
        //{
        //    if (string.IsNullOrWhiteSpace(request.Encrypted) || string.IsNullOrWhiteSpace(request.publicKey))
        //        return BadRequest("Encrypted value and SecretKey are required.");

        //    var SecretKey = _configuration["HmacAuth:Clients:mySecretKey"];
        //    if (string.IsNullOrEmpty(SecretKey))
        //        return Unauthorized("PublicKey not configured.");

        //    var combinedKey = request.publicKey + SecretKey;

        //    var decrypted = DecryptString(request.Encrypted, combinedKey);
        //    return Ok(new { Decrypted = decrypted });
        //}

        //[HttpPost("decryptwithHeaderMethod")]
        //public IActionResult Decrypt()
        //{
        //    // Read values from HTTP Headers
        //    var encryptedData = Request.Headers["X-Encrypted"].ToString();
        //    var publicKey = Request.Headers["X-PublicKey"].ToString();

        //    if (string.IsNullOrWhiteSpace(encryptedData) || string.IsNullOrWhiteSpace(publicKey))
        //        return BadRequest("X-Encrypted and X-PublicKey headers are required.");

        //    var SecretKey = _configuration["HmacAuth:Clients:mySecretKey"];
        //    if (string.IsNullOrEmpty(SecretKey))
        //        return Unauthorized("PublicKey not configured.");

        //    var combinedKey = publicKey + SecretKey;
        //    var data = DecryptString(encryptedData, combinedKey);

        //    //Response.Headers.Add("Data: ", Uri.EscapeDataString(data));

        //    Response.Headers.Add("Data", data);

        //    return Ok(new { Data = data });
        //}

        [HttpPost("decryptwithHeaderAndBody")]
        public IActionResult DecryptWithHeaderAndBody([FromBody] DecryptRequest request)
        {
            var encryptedData = Request.Headers["X-Encrypted"].ToString();
            if (string.IsNullOrWhiteSpace(encryptedData))
                return BadRequest("X-Encrypted header is required.");

            var publicKey = Request.Headers["X-publicKey"].ToString();
            if (string.IsNullOrWhiteSpace(publicKey))
                return BadRequest("PublicKey header is required.");
 
            if (string.IsNullOrWhiteSpace(request.Data))
                return BadRequest("Encrypted data is required.");

            var SecretKey = _configuration["HmacAuth:Clients:mySecretKey"];
            if (string.IsNullOrEmpty(SecretKey))
                return Unauthorized("SecretKey not configured.");

            var combinedKey = publicKey + SecretKey;
            var decryptedFromHeader = DecryptString(encryptedData, combinedKey);

            if (decryptedFromHeader == request.Data)
            {
                string textMsg = "Verification successful";
                string Emessage = EncryptString(textMsg,SecretKey);
                return Ok(new { Message = Emessage, Data = decryptedFromHeader });
            }
            else
            {
                string textMsg = "Data mismatch";
                string Emessage = EncryptString(textMsg,decryptedFromHeader,request.Data, SecretKey);
                return BadRequest(new { Message = Emessage, Expected = decryptedFromHeader, Got = request.Data });
            }
        }


        private string DecryptString(string cipherText, string key)
        {
            var fullCipher = Convert.FromBase64String(cipherText);

            using var aes = Aes.Create();
            aes.Key = SHA256.HashData(Encoding.UTF8.GetBytes(key));

            var iv = fullCipher.Take(16).ToArray();
            var cipherBytes = fullCipher.Skip(16).ToArray();
            aes.IV = iv;

            using var decryptor = aes.CreateDecryptor();
            var plainBytes = decryptor.TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);
            return Encoding.UTF8.GetString(plainBytes);
        }

        private string EncryptString(string plainText, string key)
        {
            using var aes = Aes.Create();
            aes.Key = SHA256.HashData(Encoding.UTF8.GetBytes(key));
            aes.GenerateIV();

            using var encryptor = aes.CreateEncryptor();
            var plainBytes = Encoding.UTF8.GetBytes(plainText);
            var cipherBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);

            return Convert.ToBase64String(aes.IV.Concat(cipherBytes).ToArray());
        }

        private string EncryptString(string value1, string value2, string value3, string key)
        {
            string combinedPlainText = $"{value1}|{value2}|{value3}";

            using var aes = Aes.Create();
            aes.Key = SHA256.HashData(Encoding.UTF8.GetBytes(key));
            aes.GenerateIV();

            using var encryptor = aes.CreateEncryptor();
            var plainBytes = Encoding.UTF8.GetBytes(combinedPlainText);
            var cipherBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);

            return Convert.ToBase64String(aes.IV.Concat(cipherBytes).ToArray());
        }

    }
}
