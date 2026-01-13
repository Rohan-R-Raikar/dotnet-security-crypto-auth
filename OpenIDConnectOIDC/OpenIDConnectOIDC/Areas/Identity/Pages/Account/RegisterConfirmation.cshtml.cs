// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
#nullable disable

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;
using System.Net.Mail;
using System.Text;
using System.Text.Encodings.Web;

namespace OpenIDConnectOIDC.Areas.Identity.Pages.Account
{
    [AllowAnonymous]
    public class RegisterConfirmationModel : PageModel
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IEmailSender _emailSender;
        private readonly ILogger<RegisterConfirmationModel> _logger;

        public RegisterConfirmationModel(UserManager<IdentityUser> userManager, IEmailSender emailSender, ILogger<RegisterConfirmationModel> logger)
        {
            _userManager = userManager;
            _emailSender = emailSender;
            _logger = logger;
        }

        public string Email { get; set; }
        public bool DisplayConfirmAccountLink { get; set; }
        public string EmailConfirmationUrl { get; set; }

        public async Task<IActionResult> OnGetAsync(string email, string returnUrl = null)
        {
            if (string.IsNullOrEmpty(email))
            {
                return RedirectToPage("/Index");
            }

            returnUrl ??= Url.Content("~/");

            try
            {
                var user = await _userManager.FindByEmailAsync(email);
                if (user == null)
                {
                    Response.StatusCode = 404;
                    _logger.LogWarning("User with email '{Email}' not found.", email);
                    return NotFound($"Unable to load user with email '{email}'.");
                }

                Email = email;

                DisplayConfirmAccountLink = true;

                if (DisplayConfirmAccountLink)
                {
                    var userId = await _userManager.GetUserIdAsync(user);
                    var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                    code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));

                    EmailConfirmationUrl = Url.Page(
                        "/Account/ConfirmEmail",
                        pageHandler: null,
                        values: new { area = "Identity", userId, code, returnUrl },
                        protocol: Request.Scheme);

                    await _emailSender.SendEmailAsync(email, "Confirm your email",
                        $"Please confirm your account by <a href='{HtmlEncoder.Default.Encode(EmailConfirmationUrl)}'>clicking here</a>.");
                }

                return Page();
            }
            catch (UnauthorizedAccessException uex)
            {
                _logger.LogError(uex, "Unauthorized attempt in RegisterConfirmation.");
                Response.StatusCode = 401;
                TempData["ErrorMessage"] = "Unauthorized access.";
                return RedirectToPage("./Login");
            }
            catch (System.Security.SecurityException sex)
            {
                _logger.LogError(sex, "Forbidden attempt in RegisterConfirmation.");
                Response.StatusCode = 403;
                TempData["ErrorMessage"] = "Forbidden access.";
                return RedirectToPage("./Login");
            }
            catch (SmtpException smtpex)
            {
                _logger.LogError(smtpex, "SMTP error while sending confirmation email.");
                Response.StatusCode = 500;
                TempData["ErrorMessage"] = "Failed to send confirmation email. Please try again later.";
                return Page();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error in RegisterConfirmation.");
                Response.StatusCode = 500;
                TempData["ErrorMessage"] = "An unexpected error occurred. Please try again later.";
                return Page();
            }
        }
    }
}
