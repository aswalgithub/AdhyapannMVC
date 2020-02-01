using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using System.Web.Mvc;
using Adhyapann_Project.Models;
using DataAccessLayer;

using System.Security.Claims;
using System.Web.Security;
using System.Text;
using System.Security.Cryptography;
using System.IO;


namespace Adhyapan_Project.Controllers
{


    public class AdminController : Controller
    {

        public AdhyapanDB adhyapanDB = new AdhyapanDB();
        //public AdminController(AdhyapanDB adhyapanDB)
        //{

        //    this.adhyapanDB = adhyapanDB;
        //}
        public ActionResult Login(string user, string password)
        {
            if (Authenticate(user, password))
            {
                FormsAuthentication.SetAuthCookie(user, false);
                return RedirectToAction("Index", "Admin");
            }
            else
            {
                return RedirectToAction("Index", "Auth");
            }
        }

        private bool Authenticate(string userId, string password)
        {
            AdminDetail adminDetails = adhyapanDB.GetAdminDetails(userId);
            string decryptPassword = String.Empty;

            decryptPassword = Decrypt(adminDetails.Password.ToString());

            if (userId.ToLower() == adminDetails.User_Id.ToString().ToLower() && password == decryptPassword)
                return true;
            else
                return false;
        }

        [Authorize]
        public ActionResult Index()
        {
            //AdhyapanDB adhyapanDB = new AdhyapanDB();
            List<Package> lstPackages = adhyapanDB.GetPackageDetails();
            Packages packages = new Packages();
            packages.lstPackages = lstPackages;
            return View(packages);

        }
        [Authorize]
        public ActionResult Create()
        {
            //AdhyapanDB adhyapanDB = new AdhyapanDB();
            List<Test> lstTest = adhyapanDB.GetTestDetails();
            List<BoolOptionEmailDecision> boolOptionEmailDecision = new List<BoolOptionEmailDecision>
            {
                new BoolOptionEmailDecision() { EmailDecision_ID = "", EmailDecision_Name = "Select" },

                new BoolOptionEmailDecision() { EmailDecision_ID = "1", EmailDecision_Name = "Yes" },

                new BoolOptionEmailDecision() { EmailDecision_ID = "2", EmailDecision_Name = "No" }
            };

            List<BoolOptionShared> boolOptionShared = new List<BoolOptionShared>()
            {
                new BoolOptionShared() { Shared_ID = "", Shared_Name = "Select" },

                new BoolOptionShared() { Shared_ID = "1", Shared_Name = "Yes" },

                new BoolOptionShared() { Shared_ID = "2", Shared_Name = "No" }
            };


            ViewBag.Shared = new SelectList(boolOptionShared, "Shared_ID", "Shared_Name");
            ViewBag.EmailResult = new SelectList(boolOptionEmailDecision, "EmailDecision_ID", "EmailDecision_Name");
            ViewBag.Tests = new MultiSelectList(lstTest, "Test_Name", "Test_Name");
            return View();

        }
        [Authorize]
        public ActionResult SubmitPackage(Package package, int Shared_ID, int EmailDecision_ID)
        {
            //AdhyapanDB adhyapanDB = new AdhyapanDB();
            package.Shared = Shared_ID == 1 ? true : false;
            package.Email_Result_ToUser = EmailDecision_ID == 1 ? true : false;
            package.AssociatedTests = string.Join(",", package.Test_Name);
            adhyapanDB.InsertPackage(package);
            ViewBag.result = "Record Inserted Successfully!";
            List<Test> lstTest = adhyapanDB.GetTestDetails();
            ViewBag.Tests = new MultiSelectList(lstTest, "Test_Name", "Test_Name");
            List<BoolOptionEmailDecision> boolOptionEmailDecision = new List<BoolOptionEmailDecision>
            {
                new BoolOptionEmailDecision() { EmailDecision_ID = "", EmailDecision_Name = "Select" },

                new BoolOptionEmailDecision() { EmailDecision_ID = "1", EmailDecision_Name = "Yes" },

                new BoolOptionEmailDecision() { EmailDecision_ID = "2", EmailDecision_Name = "No" }
            };

            List<BoolOptionShared> boolOptionShared = new List<BoolOptionShared>()
            {
                new BoolOptionShared() { Shared_ID = "", Shared_Name = "Select" },

                new BoolOptionShared() { Shared_ID = "1", Shared_Name = "Yes" },

                new BoolOptionShared() { Shared_ID = "2", Shared_Name = "No" }
            };
            ViewBag.Shared = new SelectList(boolOptionShared, "Shared_ID", "Shared_Name");
            ViewBag.EmailResult = new SelectList(boolOptionEmailDecision, "EmailDecision_ID", "EmailDecision_Name");

            return View("Create");
        }

        [HttpPost]
        [Authorize]
        public ActionResult SearchPackage(SearchInput input)
        {
            //AdhyapanDB adhyapanDB = new AdhyapanDB();
            List<Package> lstPackages = adhyapanDB.GetPackageDetails();
            Packages packages = new Packages();
            if (string.IsNullOrEmpty(input.PackageCode) && string.IsNullOrEmpty(input.PackageName))
            {
                packages.lstPackages = lstPackages;
            }
            else if (string.IsNullOrEmpty(input.PackageCode) && !string.IsNullOrEmpty(input.PackageName))
            {

                packages.lstPackages = lstPackages.Where(item => item.Package_Name.ToUpper().Contains(input.PackageName.ToUpper())).ToList();

            }
            else if (!string.IsNullOrEmpty(input.PackageCode) && string.IsNullOrEmpty(input.PackageName))
            {

                packages.lstPackages = lstPackages.Where(item => item.Package_Code.ToUpper().Contains(input.PackageCode.ToUpper())).ToList();

            }
            else
            {

                packages.lstPackages = lstPackages.Where(item => item.Package_Code.ToUpper().Contains(input.PackageCode.ToUpper()) && item.Package_Name.ToUpper().Contains(input.PackageName.ToUpper())).ToList();

            }
            return Json(packages);
        }



        [HttpPost]
        [Authorize]
        public ActionResult DeletePackage(int id)
        {
            //AdhyapanDB adhyapanDB = new AdhyapanDB();
            adhyapanDB.DeletePackage(id);
            Packages packages = new Packages();
            List<Package> lstPackages = adhyapanDB.GetPackageDetails();
            packages.lstPackages = lstPackages;
            return Json(packages);
        }
        [Authorize]
        public ActionResult LogOut()
        {
            FormsAuthentication.SignOut();
            return RedirectToAction("Index", "Auth");
        }

        [Authorize]
        public ActionResult SelectPackage(int id)
        {
            //AdhyapanDB adhyapanDB = new AdhyapanDB();
            Packages packages = new Packages();
            List<Package> lstPackages = adhyapanDB.GetPackageDetails(id);
            packages.lstPackages = lstPackages;
            List<Test> lstTest = adhyapanDB.GetTestDetails();
            List<BoolOptionEmailDecision> boolOptionEmailDecision = new List<BoolOptionEmailDecision>
            {
                new BoolOptionEmailDecision() { EmailDecision_ID = "", EmailDecision_Name = "Select" },

                new BoolOptionEmailDecision() { EmailDecision_ID = "1", EmailDecision_Name = "Yes" },

                new BoolOptionEmailDecision() { EmailDecision_ID = "2", EmailDecision_Name = "No" }
            };

            List<BoolOptionShared> boolOptionShared = new List<BoolOptionShared>()
            {
                new BoolOptionShared() { Shared_ID = "", Shared_Name = "Select" },

                new BoolOptionShared() { Shared_ID = "1", Shared_Name = "Yes" },

                new BoolOptionShared() { Shared_ID = "2", Shared_Name = "No" }
            };



            ViewBag.Shared = new SelectList(boolOptionShared, "Shared_ID", "Shared_Name", packages.lstPackages[0].Shared == false ? 2 : 1);
            ViewBag.EmailResult = new SelectList(boolOptionEmailDecision, "EmailDecision_ID", "EmailDecision_Name", packages.lstPackages[0].Email_Result_ToUser == false ? 2 : 1);
            ViewBag.Tests = new MultiSelectList(lstTest, "Test_Name", "Test_Name", packages.lstPackages[0].AssociatedTests.Split(',').ToList());
            return View("Edit", packages);
        }

        [Authorize]
        public ActionResult UpdatePackage(Package package, int Shared_ID, int EmailDecision_ID)
        {
            //AdhyapanDB adhyapanDB = new AdhyapanDB();
            package.Shared = Shared_ID == 1 ? true : false;
            package.Email_Result_ToUser = EmailDecision_ID == 1 ? true : false;
            package.AssociatedTests = string.Join(",", package.Test_Name);
            adhyapanDB.UpdatePackage(package);
            ViewBag.resultEdit = "Record Updated Successfully!";
            List<Test> lstTest = adhyapanDB.GetTestDetails();
            ViewBag.Tests = new MultiSelectList(lstTest, "Test_Name", "Test_Name");
            List<BoolOptionEmailDecision> boolOptionEmailDecision = new List<BoolOptionEmailDecision>
            {
                new BoolOptionEmailDecision() { EmailDecision_ID = "", EmailDecision_Name = "Select" },

                new BoolOptionEmailDecision() { EmailDecision_ID = "1", EmailDecision_Name = "Yes" },

                new BoolOptionEmailDecision() { EmailDecision_ID = "2", EmailDecision_Name = "No" }
            };

            List<BoolOptionShared> boolOptionShared = new List<BoolOptionShared>()
            {
                new BoolOptionShared() { Shared_ID = "", Shared_Name = "Select" },

                new BoolOptionShared() { Shared_ID = "1", Shared_Name = "Yes" },

                new BoolOptionShared() { Shared_ID = "2", Shared_Name = "No" }
            };
            ViewBag.Shared = new SelectList(boolOptionShared, "Shared_ID", "Shared_Name");
            ViewBag.EmailResult = new SelectList(boolOptionEmailDecision, "EmailDecision_ID", "EmailDecision_Name");
            Packages packages = new Packages();
            List<Package> lstPackages = adhyapanDB.GetPackageDetails(package.Package_ID);
            packages.lstPackages = lstPackages;

            return View("Edit", packages);
        }


        [Authorize]
        public ActionResult EditDetails(AdminDetail adminDetails)
        {
            AdminDetail DBAdmindata = adhyapanDB.GetAdminDetails("Admin");

            ViewBag.User_Id = DBAdmindata.User_Id.ToString();
            ViewBag.Password = DBAdmindata.Password.ToString();
            ViewBag.Email = DBAdmindata.Email_Id.ToString();
            if (!String.IsNullOrEmpty(adminDetails.status))
                ViewBag.status = adminDetails.status;

            return View("EditDetails");
        }

        [Authorize]
        public ActionResult EditPassword(AdminDetail adminDetails)
        {
            AdminDetail DBAdmindata = adhyapanDB.GetAdminDetails(adminDetails.User_Id.ToString());

            if (adminDetails.Password.ToString() != Decrypt(DBAdmindata.Password.ToString()))
            {
                adminDetails.status = "Fail: Currect password does not match";
            }
            else
            {
                adminDetails.Confirm_New_Password = encrypt(adminDetails.Confirm_New_Password.ToString());
                adhyapanDB.SetAdminDetails(adminDetails, "password");
                adminDetails.status = "Success: Password Updated";
            }

            return View("EditDetails", adminDetails);
        }

        [Authorize]
        public ActionResult EditEmail(AdminDetail adminDetails)
        {
            AdminDetail DBAdmindata = adhyapanDB.GetAdminDetails(adminDetails.User_Id.ToString());

            if (adminDetails.Password.ToString() != Decrypt(DBAdmindata.Password.ToString()))
            {
                adminDetails.status = "Fail: Currect password does not match";
            }
            else
            {
                adhyapanDB.SetAdminDetails(adminDetails, "email");
                adminDetails.status = "Success: Email has been updated Updated";
            }

            return View("EditDetails", adminDetails);
        }

        [Authorize]
        private string encrypt(string encryptString)
        {
            string EncryptionKey = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            byte[] clearBytes = Encoding.Unicode.GetBytes(encryptString);
            using (Aes encryptor = Aes.Create())
            {
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(EncryptionKey, new byte[] {
                    0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76
                });

                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(clearBytes, 0, clearBytes.Length);
                        cs.Close();
                    }
                    encryptString = Convert.ToBase64String(ms.ToArray());
                }
            }
            return encryptString;
        }

        [Authorize]
        private string Decrypt(string cipherText)
        {
            string EncryptionKey = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            cipherText = cipherText.Replace(" ", "+");
            byte[] cipherBytes = Convert.FromBase64String(cipherText);
            using (Aes encryptor = Aes.Create())
            {
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(EncryptionKey, new byte[] {
                    0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76
                });

                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(cipherBytes, 0, cipherBytes.Length);
                        cs.Close();
                    }
                    cipherText = Encoding.Unicode.GetString(ms.ToArray());
                }
            }
            return cipherText;
        }

        //[ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        //[Authorize]
        //public ActionResult Error()
        //{
        //    return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        //}
    }
}
