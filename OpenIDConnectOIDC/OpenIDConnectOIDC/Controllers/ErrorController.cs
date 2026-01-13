using Microsoft.AspNetCore.Mvc;

namespace OpenIDConnectOIDC.Controllers
{
    namespace OpenIDConnectOIDC.Controllers
    {
        public class ErrorController : Controller
        {
            [Route("Error")]
            public IActionResult Index(string message)
            {
                ViewData["ErrorMessage"] = message;
                return View("Error");
            }
        }
    }
}
