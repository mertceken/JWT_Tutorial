using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace JWT_Tutorial.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public static UserModel userModel = new UserModel();
        private readonly IConfiguration _configuration;


        public AuthController(IConfiguration configuration)
        {
            _configuration = configuration;
        }


        [HttpPost("Register")]
        public async Task<ActionResult<UserModel>> Register(User request)
        {
            CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);
            userModel.Username = request.Username;
            userModel.PasswordHash = passwordHash;
            userModel.PasswordSalt = passwordSalt;

            return Ok(userModel);
        }

        [HttpPost("login")]
        public async Task<ActionResult<string>> Login(User request)
        {
            if (userModel.Username == request.Username)
            {
                return BadRequest("User Not Found");
            }

            if(!VerifyPasswordHash(request.Password,userModel.PasswordHash,userModel.PasswordSalt))
            {
                return BadRequest("Wrong Password");
            }

            return Ok("My Crazy Token is approved");
        }

        private string CreateToken(UserModel userModel)
        {
            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, userModel.Username)
            };

            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(_configuration.GetSection("AppSettings:Token").Value));

            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);
            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: credentials);

            var jsonWebToken = new JwtSecurityTokenHandler().WriteToken(token);

            return jsonWebToken;
        }

        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }

        private bool VerifyPasswordHash(string password, byte[] passwordHash,byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512(passwordSalt))
            {
                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return computedHash.SequenceEqual(passwordHash);
            }
        }
    }
}
