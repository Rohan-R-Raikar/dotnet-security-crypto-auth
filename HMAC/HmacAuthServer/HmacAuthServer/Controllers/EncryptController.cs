using HmacAuthServer.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace HmacAuthServer.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class EncryptController : ControllerBase
    {
        private readonly IConfiguration _configuration;

        public EncryptController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [HttpPost("encrypt")]
        public IActionResult Encrypt([FromBody] EncryptRequest request)
        {
            if (string.IsNullOrWhiteSpace(request.Data) || string.IsNullOrWhiteSpace(request.publicKey))
                return BadRequest("Data and SecretKey are required.");

            var SecretKey = _configuration["HmacAuth:Clients:mySecretKey"];
            if (string.IsNullOrEmpty(SecretKey))
                return Unauthorized("PublicKey not configured.");

            var combinedKey = request.publicKey + SecretKey;
            var encrypted = EncryptString(request.Data, combinedKey);

            return Ok(new { Encrypted = encrypted });
        }

        [HttpPost("decrypt")]
        public IActionResult DecryptMassge()
        {
            var msg = Request.Headers["X-msg"].ToString();
            if (string.IsNullOrWhiteSpace(msg))
                return BadRequest("msg is null");

            var SecretKey = _configuration["HmacAuth:Clients:mySecretKey"];
            if (string.IsNullOrEmpty(SecretKey))
                return Unauthorized("PublicKey not configured.");

            var dmsg = DecryptString(msg, SecretKey);

            return Ok(new { Response =  dmsg });

        }

        //[HttpPost("encryptwithHeaderMethod")]
        //public IActionResult Encrypt()
        //{
        //    // Read values from HTTP Headers
        //    var data = Request.Headers["X-Data"].ToString();
        //    var publicKey = Request.Headers["X-PublicKey"].ToString();

        //    if (string.IsNullOrWhiteSpace(data) || string.IsNullOrWhiteSpace(publicKey))
        //        return BadRequest("X-Data and X-PublicKey headers are required.");

        //    var SecretKey = _configuration["HmacAuth:Clients:mySecretKey"];
        //    if (string.IsNullOrEmpty(SecretKey))
        //        return Unauthorized("PublicKey not configured.");

        //    var combinedKey = publicKey + SecretKey;
        //    var encrypted = EncryptString(data, combinedKey);

        //    Response.Headers.Add("X-Encrypted",encrypted);

        //    return Ok(new { Encrypted = encrypted });
        //}

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

    }
}
