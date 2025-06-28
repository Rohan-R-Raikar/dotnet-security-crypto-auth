using JwtAuthDotNet9.Entities;
using Microsoft.EntityFrameworkCore;

namespace JwtAuthDotNet9.Data
{
    public class ApplicationDbContext(DbContextOptions<ApplicationDbContext> options): DbContext(options)
    {
        public DbSet<User> Users { get; set; }
    }
}
