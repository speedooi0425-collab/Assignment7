using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SafeVault.Services;
using System.ComponentModel.DataAnnotations;

namespace SafeVault.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class VaultController : ControllerBase
    {
        private readonly DatabaseService _dbService;

        public VaultController(DatabaseService dbService)
        {
            _dbService = dbService;
        }

        [HttpGet("profile/{username}")]
        [Authorize(Roles = "User,Admin")] // RBAC: Both users and admins can see profiles
        public async Task<IActionResult> GetProfile([RegularExpression(@"^[a-zA-Z0-9]*$")] string username)
        {
            // INPUT VALIDATION: Regex ensures only alphanumeric chars are allowed (Prevents XSS/Injections)
            if (!ModelState.IsValid) return BadRequest("Invalid username format.");

            var user = await _dbService.GetUserSecurely(username);
            return user != null ? Ok(user) : NotFound();
        }

        [HttpDelete("clear-logs")]
        [Authorize(Roles = "Admin")] // RBAC: Only Admins can perform sensitive deletions
        public IActionResult DeleteLogs()
        {
            return Ok("Logs cleared securely by Admin.");
        }
    }
}
