using dotnetJWT.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.AspNetCore.Authorization;
using System.Web;

namespace dotnetJWT.Controllers
{   
    [ApiController]
    [Route("api/jwt")]
    
    public class JWT : ControllerBase
    {
        private IConfiguration _config;

        public JWT(IConfiguration config)
        {
            _config = config;
        }

        [HttpGet]
        public IActionResult Login(string username, string pass) {
            UserModel login = new UserModel();

            login.UserName = username;
            login.Password = pass;

            IActionResult response = new UnauthorizedResult();
            
            var user = AuthenticateUser(login);

            if(user != null) {
                var tokenStr = GenerateJSONWebToken(user);
                response = new OkObjectResult(new {token = tokenStr} );
            }

            return response;
        }
        
        [Authorize]
        [HttpPost("BP")]
        public string BP() {            
            var identity = HttpContext.User.Identity as ClaimsIdentity;
    
            IList<Claim> claim = identity.Claims.ToList();

            var bp = claim[1].Value;

            return "BP is: " + bp;
        }

        [Authorize]
        [HttpGet("GetAssort")]
        public ActionResult<IEnumerable<string>> Get() {
            var identity = HttpContext.User.Identity as ClaimsIdentity;
    
            IList<Claim> claim = identity.Claims.ToList();

            var bp = claim[1].Value;

            var test = new List<Assortment>() {
                new Assortment{ BP="333", Asort="Assortment 1"},
                new Assortment{ BP="123456", Asort="Assortment 2"}
            };

            return Ok(test.Find(x=>x.BP == bp).Asort);
        }

        private object GenerateJSONWebToken(UserModel userinfo)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var credentials = new SigningCredentials(securityKey,SecurityAlgorithms.HmacSha256);

            var claims = new[] {
                new Claim(JwtRegisteredClaimNames.Sub, userinfo.UserName),
                new Claim(JwtRegisteredClaimNames.Sid, userinfo.Bp),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var token = new JwtSecurityToken(
                issuer: _config["Jwt.Issuer"],
                audience: _config["Jwt.Audience"],
                claims,
                expires:DateTime.Now.AddMinutes(120),
                signingCredentials:credentials
            );

            var encodetoken = new JwtSecurityTokenHandler().WriteToken(token);

            return encodetoken;
        }

        private UserModel AuthenticateUser(UserModel login)
        {
            UserModel user = null;

            if(login.UserName=="adrian" && login.Password == "abc") {
                user = new UserModel { UserName="adrian", Password="abc", Bp="123456"};
            }
            return user;
        }

    }

    public class Assortment {
        public string BP { get; set; }
        public string Asort { get; set; }
    }
}