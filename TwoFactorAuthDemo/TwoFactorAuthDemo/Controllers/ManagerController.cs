using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using QRCoder;
using System.Text;
using TwoFactorAuthDemo.Models;

namespace TwoFactorAuthDemo.Controllers
{
    [Authorize]
    public class ManagerController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;

        public ManagerController(UserManager<ApplicationUser> userManager)
        {
            _userManager = userManager;
        }

        public async Task<IActionResult> TwoFactor()
        {
            var user = await _userManager.GetUserAsync(User);
            var model = new TwoFactorViewModel
            {
                Is2faEnabled = await _userManager.GetTwoFactorEnabledAsync(user)
            };

            if (model.Is2faEnabled)
            {
                var key = await _userManager.GetAuthenticatorKeyAsync(user);
                if (string.IsNullOrEmpty(key))
                {
                    await _userManager.ResetAuthenticatorKeyAsync(user);
                    key = await _userManager.GetAuthenticatorKeyAsync(user);
                }

                var authenticatorUri = $"otpauth://totp/TwoFactorAuthDemo:{user.Email}?secret={key}&issuer=TwoFactorAuthDemo";

                using var qrGenerator = new QRCodeGenerator();
                var qrData = qrGenerator.CreateQrCode(authenticatorUri, QRCodeGenerator.ECCLevel.Q);
                var qrCode = new Base64QRCode(qrData);
                model.QrCodeImageUrl = "data:image/png;base64," + qrCode.GetGraphic(20);
            }

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Toggle2fa()
        {
            var user = await _userManager.GetUserAsync(User);
            var enabled = await _userManager.GetTwoFactorEnabledAsync(user);

            if (!enabled)
            {
                await _userManager.ResetAuthenticatorKeyAsync(user);
                await _userManager.SetTwoFactorEnabledAsync(user, true);
            }
            else
            {
                await _userManager.SetTwoFactorEnabledAsync(user, false);
            }

            return RedirectToAction(nameof(TwoFactor));
        }
    }
}
