using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using TaskManager.Api.Data;
using TaskManager.Api.Models;
using TaskManager.Api.Models.Authentication;

namespace TaskManager.Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly ApplicationDbContext _context;
        private readonly IConfiguration _configuration;

        //refresh token
        private readonly TokenValidationParameters _tokenValidationParameters;

        public AuthenticationController(UserManager<ApplicationUser> userManager, 
                                        RoleManager<IdentityRole> roleManager,
                                        ApplicationDbContext context,
                                        IConfiguration configuration,
                                        TokenValidationParameters tokenValidationParameters)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _context = context;
            _configuration = configuration;
            _tokenValidationParameters = tokenValidationParameters;
        }

        [HttpPost("register-user")]
        public async Task<IActionResult> Register([FromBody]RegisterVM payload)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest("please provides all required fields.");
            }

            var userExists = await _userManager.FindByNameAsync(payload.Username);

            if(userExists != null)
            {
                return BadRequest($"{payload.Username} is already taken");
            }

            var emailExists = await _userManager.FindByEmailAsync(payload.Email);

            if (emailExists != null)
            {
                return BadRequest($"User {payload.Email} already exists");
            }

            ApplicationUser newUser = new ApplicationUser()
            {
                UserName = payload.Username,
                Email = payload.Email,
                SecurityStamp = Guid.NewGuid().ToString()
            };

            var result = await _userManager.CreateAsync(newUser, payload.Password);

            if (!result.Succeeded)
            {
                return BadRequest(result.Errors.Select(e => e.Description));
            }

            switch (payload.Role)
            {
                case "Admin":
                    await _userManager.AddToRoleAsync(newUser, UserRoles.Admin);
                    break;

                default: 
                    await _userManager.AddToRoleAsync(newUser, UserRoles.User);
                    break;
            }

            return Created(nameof(Register), $"User {payload.Username} was created");
        }

        [HttpPost("login-user")]
        public async Task<IActionResult> Login([FromBody]LoginVM payload)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest("please provides all required fields.");
            }

            var user = await _userManager.FindByEmailAsync(payload.Email);

            if(user != null && await _userManager.CheckPasswordAsync(user, payload.Password))
            {
                var tokenValue = await GenerateJwtTokenAsync(user);

                return Ok(tokenValue);
            }

            return Unauthorized();
        }

        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken([FromBody]TokenRequestVM payload)
        {
            try
            {
                var result = await VerifyAndGenerateTokenAsync(payload);

                if (result == null) return BadRequest("invalid token");

                return Ok(result);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        private async Task<AuthResultVM> VerifyAndGenerateTokenAsync(TokenRequestVM payload)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();

            // check 1 - jwt token format
            var refreshTokenValidationParameters = _tokenValidationParameters.Clone(); 
            refreshTokenValidationParameters.ValidateLifetime = false;

            var tokenInVerification = jwtTokenHandler.ValidateToken(payload.Token, refreshTokenValidationParameters, out var
                validatedToken
                );

            // check 2 - Encryption algorithm
            if(validatedToken is JwtSecurityToken jwtSecurityToken)
            {
                var result = jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256,
                    StringComparison.InvariantCultureIgnoreCase);

                if(result == false) return null;
            }

            // check 3 - validate expiry data
            var utcExpiryData = long.Parse(tokenInVerification.Claims.FirstOrDefault(
                                            x => x.Type == JwtRegisteredClaimNames.Exp).Value);

            var expiryDate = UnixTimeStampToDateTimeInUTC(utcExpiryData);
            if (expiryDate > DateTime.UtcNow) throw new Exception("token has not expired yet");

            //check 4 - refresh token exists in database
            var hashedRefreshToken = HashRefreshToken(payload.RefreshToken);

            var dbRefreshToken = await _context.RefreshTokens.FirstOrDefaultAsync(
                                                              n => n.Token == hashedRefreshToken);
            if(dbRefreshToken == null) throw new Exception("refresh token does not exist in db");
            else
            {
                //check 5 - validate id
                var jti = tokenInVerification.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Jti).Value;

                if(dbRefreshToken.JwtId != jti) throw new Exception("token does not match");

                //check 6 - refresh token expiration
                if(dbRefreshToken.DateExpire <= DateTime.UtcNow) throw new Exception("your refresh token has expired," +
                    "please re-authenticate");

                //check 7 - refresh token revoked
                if(dbRefreshToken.IsRevoked) throw new Exception("refresh token is revoked");

                // generate new token
                var dbUserData = await _userManager.FindByIdAsync(dbRefreshToken.UserId);

                if(dbUserData == null) throw new Exception("User does not exist.");

                dbRefreshToken.IsRevoked = true;
                await _context.SaveChangesAsync();

                var newTokenResponse = GenerateJwtTokenAsync(dbUserData);

                return await newTokenResponse;
            }
        }

        private async Task<AuthResultVM> GenerateJwtTokenAsync(ApplicationUser user)
        {
            var authClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            //add user roles
            var userRoles = await _userManager.GetRolesAsync(user);
            foreach(var role in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, role));
            }

            var secret = _configuration["JWT:Secret"] ?? throw new InvalidOperationException("JWT:Secret is missing");
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));

            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:Issuer"],
                audience: _configuration["JWT:Audience"],
                expires: DateTime.UtcNow.AddMinutes(5), 
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                );

            var jwtToken = new JwtSecurityTokenHandler().WriteToken(token);
            var refreshToken = new RefreshToken();

            var rawRefreshToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));

            refreshToken = new RefreshToken()
            {
                JwtId = token.Id,
                IsRevoked = false,
                UserId = user.Id,
                DateAdded = DateTime.UtcNow,
                DateExpire = DateTime.UtcNow.AddMonths(6),
                Token = HashRefreshToken(rawRefreshToken)
            };

            await _context.RefreshTokens.AddAsync(refreshToken);
            await _context.SaveChangesAsync();
            

            var response = new AuthResultVM()
            {
                Token = jwtToken,
                RefreshToken = rawRefreshToken,
                ExpiresAt = token.ValidTo //automatically generated
            };
            return response;
        }

        private static string HashRefreshToken(string refreshToken)
        {
            var tokenBytes = Encoding.UTF8.GetBytes(refreshToken);
            var hashBytes = SHA256.HashData(tokenBytes);

            return Convert.ToHexString(hashBytes);
        }

        private DateTime UnixTimeStampToDateTimeInUTC(long unixTimeStamp)
        {
            var dateTimeValue = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            dateTimeValue = dateTimeValue.AddSeconds(unixTimeStamp);
            return dateTimeValue;
        }
    }
}
