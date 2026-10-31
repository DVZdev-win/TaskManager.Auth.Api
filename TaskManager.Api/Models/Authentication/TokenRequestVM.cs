namespace TaskManager.Api.Models.Authentication
{
    public class TokenRequestVM
    {
        public string Token { get; set; }
        public string RefreshToken { get; set; }
    }
}
