namespace JWTcontinueIfSessionActive.Models
{
    public class UserSession
    {
        public int Id { get; set; }
        public int UserId { get; set; }
        public DateTime LastActivity { get; set; }
    }
}
