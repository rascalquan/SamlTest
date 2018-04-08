using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Web;
using System.Web.Mvc;
using System.Xml;
using SeamTest2.BLL;

namespace SeamTest2
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }

        public ActionResult About()
        {
            ViewBag.Message = "Your application description page.";

            return View();
        }

        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }

        public ActionResult OneLogin()
        {
            if (true)
            {
                return Redirect("~/home/SamlTest");
            }
            else
            {
                return View(); 
            }
        }

        public ActionResult SamlTest()
        {
            AccountSettings accountSettings = new AccountSettings();

            AuthRequest req = new AuthRequest(new AppSettings(),
            accountSettings);

            string url = req.GetRedirectUrl(accountSettings.idp_sso_target_url);

            return Redirect(url);
        }

        public ActionResult Acs(string response)
        {
            // replace with an instance of the users account.
            AccountSettings accountSettings = new AccountSettings();

            Response samlResponse = new Response(accountSettings);
            samlResponse.LoadXmlFromBase64(response);

            if (samlResponse.IsValid())
            {
                return Content("OK:" + samlResponse.GetNameID());
            }
            else
            {
                return Content("Failed");
            }
        }

        public ActionResult SamlTest2()
        {
            string issuer = "prog1";
            X509Certificate2 cert = SesameUtils2.GetSigningCertificate();

            SesameUtils2 s2 = new SesameUtils2();
            XmlDocument doc = s2.GetAuthnRequest(issuer);
            //doc.Save("phase1.xml");
            XmlDocument doc2 = s2.SignXmlDocumentFinal(doc, cert, true);  //true - false - does not matter
            //doc2.Save("phase2.xml");
            XmlDocument doc3 = s2.CallSoap(doc2);
            //doc3.Save("phase3.xml");
            return Content(doc3.InnerXml);
        }
    }
}