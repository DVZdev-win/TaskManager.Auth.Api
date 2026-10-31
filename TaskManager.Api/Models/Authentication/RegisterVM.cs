using System.ComponentModel.DataAnnotations;

namespace TaskManager.Api.Models.Authentication
{
    public class RegisterVM
    {
        [Required(ErrorMessage ="username is required")]
        public string Username { get; set; }

        [Required(ErrorMessage = "email is required")]
        [EmailAddress(ErrorMessage ="email address is invalid")]
        public string Email { get; set; }

        [Required(ErrorMessage = "password is required")]
        public string Password { get; set; }

        [Required(ErrorMessage = "role is required")]
        public string Role { get; set; }
    }
}
