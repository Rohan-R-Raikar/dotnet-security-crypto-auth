namespace HmacAuthServer.Models
{
    public class EncryptRequest
    {
        public string Data { get; set; } = string.Empty;
        public string publicKey { get; set; } = string.Empty;
    }
}
