using JWTAuthenticationManager;
using JWTAuthenticationManager.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace AuthenticationWebAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly JwtTokenHandler _jwtTokenHandler;
        public AccountController(JwtTokenHandler jwtTokenHandler)
        {
                _jwtTokenHandler = jwtTokenHandler;
        }

        [HttpPost ]
        public ActionResult<AuthenticationResponse?> Authenticate([FromBody]AuthenticationRequest request)
        {
            var authenticationResponse=_jwtTokenHandler .GenerateJwtToken(request);
            if(authenticationResponse == null)  return Unauthorized();
            return authenticationResponse;
        }
    }
}
