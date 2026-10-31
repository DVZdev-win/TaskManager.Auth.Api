using System.ComponentModel.DataAnnotations;

namespace TaskManager.Api.Models.Authentication
{
    public class LoginVM
    {
        [Required(ErrorMessage ="Email is required")]
        [EmailAddress(ErrorMessage = "Email address is invalid")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Password is required")]
        public string Password { get; set; }

    }
}
