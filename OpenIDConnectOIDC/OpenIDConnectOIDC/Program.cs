using HealthChecks.UI.Client;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using OpenIDConnectOIDC.Data;
using OpenIDConnectOIDC.Helpers;
using OpenIDConnectOIDC.Models;
using OpenIDConnectOIDC.Services;


var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllersWithViews();

builder.Services.AddHttpClient();

builder.Services.AddHealthChecks()
    .AddSqlServer(
        connectionString: builder.Configuration.GetConnectionString("DefaultConnection"),
        name: "Database",
        failureStatus: Microsoft.Extensions.Diagnostics.HealthChecks.HealthStatus.Unhealthy,
        tags: new[] { "db", "sql" })
    .AddSmtpHealthCheck(options =>
    {
        options.Host = builder.Configuration["EmailSettings:Host"];
        options.Port = int.Parse(builder.Configuration["EmailSettings:Port"] ?? "587");
        options.AllowInvalidRemoteCertificates = true;
    }, name: "SMTP", failureStatus: HealthStatus.Degraded, tags: new[] { "email" })
    .AddDiskStorageHealthCheck(s =>
    {
        s.AddDrive("C:\\", 1024);
    }, name: "Disk Space", failureStatus: HealthStatus.Degraded, tags: new[] { "system", "storage" })

    .AddCheck("Memory", () =>
    {
        var memoryUsed = GC.GetTotalMemory(false);
        return memoryUsed < 1024 * 1024 * 500
            ? HealthCheckResult.Healthy($"Memory OK: {memoryUsed / 1024 / 1024} MB used")
            : HealthCheckResult.Degraded($"High memory usage: {memoryUsed / 1024 / 1024} MB");
    }, tags: new[] { "system", "memory" });

builder.Services.AddHealthChecksUI(options =>
{
    options.SetEvaluationTimeInSeconds(15);
    options.MaximumHistoryEntriesPerEndpoint(50);
    options.AddHealthCheckEndpoint("Main Health Check", "/health");
})
.AddInMemoryStorage();


builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddIdentity<IdentityUser, IdentityRole>(options =>
{
    options.SignIn.RequireConfirmedAccount = true;
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders()
.AddDefaultUI();

builder.Services.AddSingleton<JwtTokenGenerator>();

builder.Services.Configure<EmailSettingsModel>(builder.Configuration.GetSection("EmailSettings"));
builder.Services.AddTransient<IEmailSender, SmtpEmailSender>();

builder.Services.AddAuthentication()
    .AddGoogle(options =>
    {
        options.ClientId = builder.Configuration["Authentication:Google:ClientId"];
        options.ClientSecret = builder.Configuration["Authentication:Google:ClientSecret"];
        options.SignInScheme = IdentityConstants.ExternalScheme;

        options.Scope.Clear();
        options.Scope.Add("openid");
        options.Scope.Add("email");
        options.Scope.Add("profile");

        options.Events.OnRedirectToAuthorizationEndpoint = context =>
        {
            var redirectUri = context.RedirectUri;
            redirectUri += "&prompt=select_account";
            context.Response.Redirect(redirectUri);
            return Task.CompletedTask;
        };

        options.Events.OnRemoteFailure = context =>
        {
            var logger = context.HttpContext.RequestServices
                        .GetRequiredService<ILogger<Program>>();
            logger.LogError(context.Failure, "Google authentication failed.");
            context.Response.Redirect("/Error?message=" + Uri.EscapeDataString(context.Failure.Message));
            context.HandleResponse();
            return Task.CompletedTask;
        };
    })
    .AddFacebook(options =>
    {
        options.AppId = builder.Configuration["Authentication:Facebook:AppId"];
        options.AppSecret = builder.Configuration["Authentication:Facebook:AppSecret"];
        options.SignInScheme = IdentityConstants.ExternalScheme;

        // Optional: request additional fields
        options.Fields.Add("name");
        options.Fields.Add("email");
        options.Fields.Add("picture");

        options.Events.OnRemoteFailure = context =>
        {
            var logger = context.HttpContext.RequestServices
                        .GetRequiredService<ILogger<Program>>();
            logger.LogError(context.Failure, "Facebook authentication failed.");
            context.Response.Redirect("/Error?message=" + Uri.EscapeDataString(context.Failure.Message));
            context.HandleResponse();
            return Task.CompletedTask;
        };

    });




var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseExceptionHandler("/Error");

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.MapRazorPages();

app.MapHealthChecks("/health", new Microsoft.AspNetCore.Diagnostics.HealthChecks.HealthCheckOptions
{
    ResponseWriter = UIResponseWriter.WriteHealthCheckUIResponse
});

app.MapHealthChecksUI(options =>
{
    options.UIPath = "/health-ui";
    options.ApiPath = "/health-ui-api";
});


app.Run();
