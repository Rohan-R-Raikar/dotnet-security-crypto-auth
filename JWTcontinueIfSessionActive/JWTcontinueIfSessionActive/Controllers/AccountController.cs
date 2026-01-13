using JWTcontinueIfSessionActive.Data;
using JWTcontinueIfSessionActive.Helper;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using System.Security.Claims;

namespace JWTcontinueIfSessionActive.Controllers
{
    public class AccountController : Controller
    {
        private readonly JwtService _jwtService;
        private readonly ApplicationDbContext _context;
        private readonly IConfiguration _config;
        private readonly IMemoryCache _memoryCache;

        public AccountController(
            JwtService jwtService,
            ApplicationDbContext context,
            IConfiguration config,
            IMemoryCache memoryCache)
        {
            _jwtService = jwtService;
            _context = context;
            _config = config;
            _memoryCache = memoryCache;
        }

        [HttpGet]
        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Login(string username, string password)
        {
            var user = _context.Users
                .FirstOrDefault(u => u.Username == username && u.Password == password);

            if (user == null)
            {
                TempData["LoginError"] = "Invalid username or password";
                return RedirectToAction("Login");
            }

            var token = _jwtService.GenerateToken(user.Id.ToString(), user.Username);

            Response.Cookies.Append("AccessToken", token, new CookieOptions
            {
                HttpOnly = true,
                Secure = false
            });

            string sessionId = Guid.NewGuid().ToString();

            int timeoutMinutes = int.Parse(
                _config["SessionSettings:SessionTimeoutMinutes"]);

            //string cacheKey = $"session_{user.Username}_{sessionId}";
            string cacheKey = $"session_{user.Id}_{sessionId}";

            _memoryCache.Set(cacheKey, true,
                TimeSpan.FromMinutes(timeoutMinutes));

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()), // <-- REQUIRED
                new Claim(ClaimTypes.Name, user.Username),
                new Claim("SessionId", sessionId)
            };


            var identity = new ClaimsIdentity(
                claims,
                CookieAuthenticationDefaults.AuthenticationScheme);

            var authProps = new AuthenticationProperties
            {
                IsPersistent = false
            };

            //authProps.Items["SessionId"] = sessionId;

            await HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                new ClaimsPrincipal(identity),
                authProps
            );

            return RedirectToAction("Index", "Home");
        }

        [HttpPost]
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(
                CookieAuthenticationDefaults.AuthenticationScheme);

            //var username = User.Identity?.Name;
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var sessionId = User.FindFirst("SessionId")?.Value;

            if (userId != null && sessionId != null)
            {
                _memoryCache.Remove($"session_{userId}_{sessionId}");
            }

            Response.Cookies.Delete("AccessToken");

            return RedirectToAction("Login");
        }

        [Authorize]
        [HttpPost]
        public IActionResult ButtonClick()
        {
            return Json(new { success = true, message = "Button Clicked Successfully!" });
        }

        public IActionResult SessionTimeout()
        {
            return View();
        }
    }
}
