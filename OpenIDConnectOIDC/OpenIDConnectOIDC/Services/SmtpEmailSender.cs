using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.Extensions.Options;
using OpenIDConnectOIDC.Models;
using System.Net;
using System.Net.Mail;
using System.Text;
using System.Threading.Tasks;

namespace OpenIDConnectOIDC.Services
{
    public class SmtpEmailSender : IEmailSender
    {
        private readonly EmailSettingsModel _emailSettings;

        public SmtpEmailSender(IOptions<EmailSettingsModel> emailSettings)
        {
            _emailSettings = emailSettings.Value;
        }

        public Task SendEmailAsync(string email, string subject, string htmlMessage)
        {
            var client = new SmtpClient(_emailSettings.Host, _emailSettings.Port)
            {
                EnableSsl = _emailSettings.EnableSSL,
                Credentials = new NetworkCredential(_emailSettings.UserName, _emailSettings.Password)
            };

            var builder = new StringBuilder();
            builder.AppendLine("<!DOCTYPE html>");
            builder.AppendLine("<html lang='en'>");
            builder.AppendLine("<head>");
            builder.AppendLine("<meta charset='UTF-8'>");
            builder.AppendLine("<meta name='viewport' content='width=device-width, initial-scale=1.0'>");
            builder.AppendLine("<style>");
            builder.AppendLine("  body { font-family: Arial, sans-serif; background-color: #f7f7f7; margin:0; padding:0; }");
            builder.AppendLine("  .container { max-width: 600px; margin: 40px auto; background-color: #ffffff; border-radius: 8px; padding: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }");
            builder.AppendLine("  .header { font-size: 24px; font-weight: bold; color: #333333; margin-bottom: 10px; text-align: center; }");
            builder.AppendLine("  .content { font-size: 16px; color: #555555; line-height: 1.5; margin-bottom: 20px; }");
            builder.AppendLine("  .button { display: inline-block; padding: 12px 24px; font-size: 16px; color: #ffffff; background-color: #007bff; border-radius: 5px; text-decoration: none; }");
            builder.AppendLine("  .footer { font-size: 12px; color: #999999; text-align: center; margin-top: 30px; }");
            builder.AppendLine("</style>");
            builder.AppendLine("</head>");
            builder.AppendLine("<body>");
            builder.AppendLine("<div class='container'>");
            builder.AppendLine("<div class='header'>OpenIDConnectOIDC</div>");
            builder.AppendLine("<div class='content'>");
            builder.AppendLine(htmlMessage);
            builder.AppendLine("</div>");
            builder.AppendLine("<div class='footer'>If you did not request this email, please ignore it.<br/>© 2025 OpenIDConnectOIDC. All rights reserved.</div>");
            builder.AppendLine("</div>");
            builder.AppendLine("</body>");
            builder.AppendLine("</html>");

            var mailMessage = new MailMessage
            {
                From = new MailAddress(_emailSettings.From, "OpenIDConnectOIDC Team"),
                Subject = subject,
                Body = builder.ToString(),
                IsBodyHtml = true
            };

            mailMessage.To.Add(email);

            return client.SendMailAsync(mailMessage);
        }
    }
}
