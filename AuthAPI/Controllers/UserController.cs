using AuthAPI.Context;
using AuthAPI.Helpers;
using AuthAPI.Models;
using AuthAPI.Models.Dto;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace AuthAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController: ControllerBase
    {
        private readonly AuthDbContext _authContext;

        public UserController(AuthDbContext appDbContext)
        {
            _authContext = appDbContext;
        }

        /// <summary>
        /// Authenticate the user with user name and password
        /// </summary>
        /// <param name="userObj">username and password</param>
        /// <returns>new token and refresh token</returns>
        [HttpPost("authenticate")]
        public async Task<IActionResult> Authenticate([FromBody] User userObj)
        {
            if (userObj == null)
                return BadRequest(Constants.InvalidRequest);
            var user = await _authContext.Users.FirstOrDefaultAsync(x => x.UserName == userObj.UserName);
            if (user == null)
            {
                return NotFound(new { Message = Constants.UserNotFound });
            }
            if (!PasswordHasher.verifyPassword(userObj.Password, user.Password))
            {
                return BadRequest(new { Message = Constants.PasswordIncorrect });
            }
            user.Token = Createjwt(user);
            var newAccessToken = user.Token;
            var newRefreshToken = CreateRefreshToken();
            user.RefreshToken = newRefreshToken;
            user.RefreshTokenExpiryTime = DateTime.Now.AddDays(1);
            await _authContext.SaveChangesAsync();
            return Ok(new TokenApiDto()
            {
                AccessToken = newAccessToken,
                RefreshToken = newRefreshToken
            });
        }

        /// <summary>
        /// register the new user with details
        /// </summary>
        /// <param name="userObj">will have all user details including password</param>
        /// <returns>will return success message</returns>
        [HttpPost("register")]
        public async Task<IActionResult> RegisterUser([FromBody] User userObj)
        {
            if (userObj == null)
                return BadRequest(Constants.InvalidRequest);
            if (await CheckUserNameExistAsync(userObj.UserName))
                return BadRequest(new { Message = Constants.UserExist });
            if (await CheckEmailExistAsync(userObj.Email))
                return BadRequest(new { Message = Constants.EmailExist });

            var pass = CheckPasswordStrength(userObj.Password);
            if (!string.IsNullOrEmpty(pass))
                return BadRequest(new { Message = pass.ToString() });

            userObj.Password = PasswordHasher.HashPassword(userObj.Password);

            userObj.Role = Constants.UserRole;
            userObj.Token = string.Empty;

            await _authContext.Users.AddAsync(userObj);
            await _authContext.SaveChangesAsync();
            return Ok(new
            {
                Message = Constants.UserRegistered
            });
        }

        /// <summary>
        /// refresh token by creating new token by passing old token
        /// </summary>
        /// <param name="tokenApiDto">Access token and Refresh token</param>
        /// <returns>new Access token and Refresh token</returns>
        [HttpPost("Refresh")]
        public async Task<IActionResult> Refresh(TokenApiDto tokenApiDto)
        {
            if (tokenApiDto is null)
                return BadRequest(Constants.InvalidRequest);

            string accessToken = tokenApiDto.AccessToken;
            string refreshToken = tokenApiDto.RefreshToken;
            var principle = GetPrincipleFromExpiredToken(accessToken);
            var username = principle.Identity.Name;
            var user = await _authContext.Users.FirstOrDefaultAsync(u => u.UserName == username);
            if (user is null || user.RefreshToken != refreshToken || user.RefreshTokenExpiryTime <= DateTime.Now)
                return BadRequest(Constants.InvalidRequest);
            var newAccessToken = Createjwt(user);
            var newRefreshToken = CreateRefreshToken();
            user.RefreshToken = newRefreshToken;
            await _authContext.SaveChangesAsync();
            return Ok(new TokenApiDto()
            {
                AccessToken = newAccessToken,
                RefreshToken = newRefreshToken,
            });
        }

        /// <summary>
        /// Check UserName
        /// </summary>
        private Task<bool> CheckUserNameExistAsync(string username) =>
            _authContext.Users.AnyAsync(x => x.UserName == username);

        /// <summary>
        /// Check email
        /// </summary>
        private Task<bool> CheckEmailExistAsync(string email) =>
           _authContext.Users.AnyAsync(x => x.Email == email);

        /// <summary>
        /// Check password strength
        /// </summary>
        private string CheckPasswordStrength(string password)
        {
            StringBuilder sb = new StringBuilder();
            if (password.Length < 8)
                sb.Append(Constants.MinPasswordlength + Environment.NewLine);
            if (!(Regex.IsMatch(password, "[a-z]") && Regex.IsMatch(password, "[A-Z]")
                && Regex.IsMatch(password, "[0-9]")))
                sb.Append(Constants.AlphanumericPassword + Environment.NewLine);
            if (!Regex.IsMatch(password, Constants.EmailRegex))
                sb.Append(Constants.SpecialCharPassword + Environment.NewLine);

            return sb.ToString();
        }

        /// <summary>
        /// create jwt token 
        /// </summary>
        private string Createjwt(User user)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(Constants.SecurityCode);
            var adminEmail = _authContext.Users.Where(x => x.Role!.ToLower() == Constants.AdminRole).Select(x => x.Email).FirstOrDefault();
            var identity = new ClaimsIdentity(new Claim[]
            {
                new Claim(ClaimTypes.Role,$"{user.Role}"),
                new Claim(ClaimTypes.Name,$"{user.UserName}"),
                new Claim(ClaimTypes.Email,$"{user.Email}"),
                new Claim(Constants.UserId,user.Id.ToString()),
                new Claim(Constants.AdminEmail,$"{adminEmail}")

            });
            var credentisal = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256);
            var tokenDescription = new SecurityTokenDescriptor
            {
                Subject = identity,
                Expires = DateTime.Now.AddMinutes(5),
                SigningCredentials = credentisal
            };
            var token = jwtTokenHandler.CreateToken(tokenDescription);
            return jwtTokenHandler.WriteToken(token);

        }

        /// <summary>
        /// Create refresh token
        /// </summary>
        private string CreateRefreshToken()
        {
            var tokenBytes = RandomNumberGenerator.GetBytes(64);
            var refreshToken = Convert.ToBase64String(tokenBytes);
            var tokenInUser = _authContext.Users.Any(a => a.RefreshToken == refreshToken);

            if (tokenInUser)
            {
                return CreateRefreshToken();
            }
            return refreshToken;
        }

        /// <summary>
        /// Get payload from expired token
        /// </summary>
        /// <param name="token">expired token</param>
        private ClaimsPrincipal GetPrincipleFromExpiredToken(string token)
        {
            var key = Encoding.ASCII.GetBytes(Constants.SecurityCode);
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateLifetime = false
            };
            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken;
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out securityToken);
            var jwtsecuritytoken = securityToken as JwtSecurityToken;
            if (jwtsecuritytoken == null || !jwtsecuritytoken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException(Constants.InvalidToken);
            return principal;
        }

    }
}
