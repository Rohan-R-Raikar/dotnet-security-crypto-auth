using Microsoft.AspNetCore.Mvc;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using System.Collections.Generic;
using OpenIDConnectOIDC.Models;

namespace OpenIDConnectOIDC.Controllers.ApiControllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class PincodeController : ControllerBase
    {
        private readonly IHttpClientFactory _httpClientFactory;

        public PincodeController(IHttpClientFactory httpClientFactory)
        {
            _httpClientFactory = httpClientFactory;
        }

        [HttpGet("{pincode}")]
        public async Task<IActionResult> GetPincodeInfo(string pincode)
        {
            try
            {
                var client = _httpClientFactory.CreateClient();
                var response = await client.GetAsync($"http://www.postalpincode.in/api/pincode/{pincode}");

                if (!response.IsSuccessStatusCode)
                    return NotFound(new { message = "PIN code not found." });

                var content = await response.Content.ReadAsStringAsync();
                using var jsonDoc = JsonDocument.Parse(content);
                var root = jsonDoc.RootElement;

                if (!root.TryGetProperty("PostOffice", out var postOffices) ||
                    postOffices.ValueKind != JsonValueKind.Array ||
                    postOffices.GetArrayLength() == 0)
                {
                    return NotFound(new { message = "No data available for the provided PIN code." });
                }

                var firstPostOffice = postOffices[0];

                var result = new
                {
                    Pincode = root.TryGetProperty("Pincode", out var p) ? p.GetString() : pincode,
                    District = firstPostOffice.TryGetProperty("District", out var d) ? d.GetString() : null,
                    State = firstPostOffice.TryGetProperty("State", out var s) ? s.GetString() : null,
                    Country = "India"
                };

                return Ok(result);
            }
            catch
            {
                return StatusCode(500, new { message = "Internal server error." });
            }
        }

    }
}
