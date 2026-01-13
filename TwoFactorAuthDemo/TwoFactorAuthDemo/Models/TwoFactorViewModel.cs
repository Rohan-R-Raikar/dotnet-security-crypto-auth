namespace TwoFactorAuthDemo.Models
{
    public class TwoFactorViewModel
    {
        public bool Is2faEnabled { get; set; }
        public string QrCodeImageUrl { get; set; }
    }
}
