using JWTcontinueIfSessionActive.Data;
using JWTcontinueIfSessionActive.Helper;
using JWTcontinueIfSessionActive.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using System.Security.Claims;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddMemoryCache();

builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddScoped<JwtService>();

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/Account/Login";
        options.ExpireTimeSpan = TimeSpan.FromMinutes(2);
        options.SlidingExpiration = true;
        options.Cookie.HttpOnly = true;
        options.Cookie.SameSite = SameSiteMode.Lax;
        options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
    });

builder.Services.AddControllersWithViews();

var app = builder.Build();

app.UseStaticFiles();

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

//app.Use(async (context, next) =>
//{
//    if (context.User.Identity?.IsAuthenticated == true)
//    {
//        var userId = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
//        var sessionId = context.User.FindFirst("SessionId")?.Value;

//        if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(sessionId))
//        {
//            await context.SignOutAsync();
//            context.Response.Redirect("/Account/Login");
//            return;
//        }

//        var cache = context.RequestServices.GetRequiredService<IMemoryCache>();
//        var config = context.RequestServices.GetRequiredService<IConfiguration>();

//        string cacheKey = $"session_{userId}_{sessionId}";

//        if (!cache.TryGetValue(cacheKey, out _))
//        {
//            await context.SignOutAsync();
//            context.Response.Redirect("/Account/SessionTimeout");
//            return;
//        }

//        cache.Set(
//            cacheKey,
//            true,
//            TimeSpan.FromMinutes(
//                int.Parse(config["SessionSettings:SessionTimeoutMinutes"])
//            )
//        );

//        if (cache.TryGetValue(cacheKey, out var value))
//        {
//            Console.WriteLine($"Cache set successfully! Key: {cacheKey}, Value: {value}");
//        }
//        else
//        {
//            Console.WriteLine($"Failed to set cache for Key: {cacheKey}");
//        }
//    }

//    await next();
//});

app.Use(async (context, next) =>
{
    if (context.User.Identity?.IsAuthenticated == true)
    {
        var userId = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var sessionId = context.User.FindFirst("SessionId")?.Value;

        if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(sessionId))
        {
            await context.SignOutAsync();
            context.Response.Redirect("/Account/Login");
            return;
        }

        var cache = context.RequestServices.GetRequiredService<IMemoryCache>();
        var config = context.RequestServices.GetRequiredService<IConfiguration>();

        string cacheKey = $"session_{userId}_{sessionId}";
        int timeoutMinutes = int.Parse(config["SessionSettings:SessionTimeoutMinutes"]);
        DateTime expiryTime = DateTime.UtcNow.AddMinutes(timeoutMinutes);

        // Store object with value + expiry time
        cache.Set(cacheKey, new { Value = true, Expiry = expiryTime }, TimeSpan.FromMinutes(timeoutMinutes));

        // Read and print remaining time
        if (cache.TryGetValue(cacheKey, out var cacheEntry))
        {
            var remaining = ((dynamic)cacheEntry).Expiry - DateTime.UtcNow;
            Console.WriteLine($"Cache Key: {cacheKey}, Value: {((dynamic)cacheEntry).Value}, Remaining Time: {remaining.TotalSeconds:F0} seconds");
        }
        else
        {
            Console.WriteLine($"Failed to set cache for Key: {cacheKey}");
        }
    }

    await next();
});


app.MapDefaultControllerRoute();

app.Run();
