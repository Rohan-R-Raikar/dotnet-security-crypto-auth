using Google.Apis.Auth;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenIDConnectOIDC.Helpers;

namespace OpenIDConnectOIDC.Controllers.ApiControllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthApiController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly JwtTokenGenerator _jwtTokenGenerator;
        private readonly IConfiguration _configuration;

        public AuthApiController(
            UserManager<IdentityUser> userManager,
            JwtTokenGenerator jwtTokenGenerator,
            IConfiguration configuration)
        {
            _userManager = userManager;
            _jwtTokenGenerator = jwtTokenGenerator;
            _configuration = configuration;
        }

        [HttpPost("google")]
        public async Task<IActionResult> GoogleLogin([FromBody] GoogleLoginRequest request)
        {
            if (string.IsNullOrEmpty(request?.IdToken))
                return BadRequest(new { Message = "IdToken is required" });

            GoogleJsonWebSignature.Payload payload;

            try
            {
                var settings = new GoogleJsonWebSignature.ValidationSettings
                {
                    Audience = new[] { _configuration["Authentication:Google:ClientId"] }
                };

                payload = await GoogleJsonWebSignature.ValidateAsync(request.IdToken, settings);
            }
            catch (Exception ex)
            {
                return Unauthorized(new { Message = "Invalid Google token", Details = ex.Message });
            }

            var user = await _userManager.FindByEmailAsync(payload.Email);
            if (user == null)
            {
                user = new IdentityUser
                {
                    UserName = payload.Email,
                    Email = payload.Email,
                    EmailConfirmed = true
                };

                var result = await _userManager.CreateAsync(user);
                if (!result.Succeeded)
                {
                    return StatusCode(500, new { Message = "Failed to create user", Errors = result.Errors });
                }

                var loginInfo = new UserLoginInfo("Google", payload.Subject, "Google");
                var loginResult = await _userManager.AddLoginAsync(user, loginInfo);
                if (!loginResult.Succeeded)
                {
                    return StatusCode(500, new { Message = "Failed to link Google login", Errors = loginResult.Errors });
                }
            }

            var token = _jwtTokenGenerator.GenerateToken(user);

            return Ok(new
            {
                Token = token,
                Email = user.Email,
                UserId = user.Id
            });
        }
    }

    public class GoogleLoginRequest
    {
        public string IdToken { get; set; }
    }
}
