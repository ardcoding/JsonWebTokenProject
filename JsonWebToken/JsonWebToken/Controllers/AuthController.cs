using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JsonWebToken.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        string signinKey = "Buraya uzun bir şey yazmalıymışım";
        [HttpGet]
        public string GetToken(string Name, string Password)
        {
            var claims = new[]
            {
                new Claim(ClaimTypes.Name, Name),
                new Claim(JwtRegisteredClaimNames.Name, Name),
            };

            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signinKey));
            var credentials = new SigningCredentials(securityKey,SecurityAlgorithms.HmacSha256);
            var jwtToken = new JwtSecurityToken(
                issuer: "https://www.example.com",
                audience: "audience",
                claims: claims,
                signingCredentials: credentials
                );
            var token = new JwtSecurityTokenHandler().WriteToken(jwtToken);
            return token;
        }

        [HttpGet("TokenValidation")]
        public bool TokenValidation(string token)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signinKey));

            try
            {
                JwtSecurityTokenHandler handler = new();
                handler.ValidateToken(token, new TokenValidationParameters()
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = securityKey,
                    ValidateLifetime = false,
                    ValidateAudience = false,
                    ValidateIssuer = false
                }, out SecurityToken validatedToken);

                var jwtToken = (JwtSecurityToken)validatedToken;
                var claims = jwtToken.Claims.ToList();
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}
