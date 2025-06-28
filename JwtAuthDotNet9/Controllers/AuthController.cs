using JwtAuthDotNet9.Entities;
using JwtAuthDotNet9.Models;
using JwtAuthDotNet9.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JwtAuthDotNet9.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController(IAuthService authService) : Controller
    {
        public static User user = new();
        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserDto request)
        {
            var user = await authService.RegisterAsync(request);
            if (user is null)
                return BadRequest("UserName Already Exists");

            return Ok(user);    
        }

        [HttpPost("login")]
        public async Task<ActionResult<string>> Login(UserDto request)
        {
            var token = await authService.LoginAsync(request);
            if (token is null)
                return BadRequest("Invalid username or password");
            
            return Ok(token);
        }

        [Authorize]
        [HttpGet]
        public IActionResult AuthenticationOnlyEndPoint()
        {
            return Ok("You are Authenticated");
        }

        [Authorize(Roles = "Admin")]
        [HttpGet("admin-only")]
        public IActionResult AdminOnlyEndPoint()
        {
            return Ok("You are Admin!");
        }

        [Authorize(Roles = "User")]
        [HttpGet("user-only")]
        public IActionResult UserOnlyEndPoint()
        {
            return Ok("You are User!");
        }
    }
}
