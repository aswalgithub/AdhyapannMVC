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

            if (user == "Admin" && password == "Password")
            {
                FormsAuthentication.SetAuthCookie(user, false);

                return RedirectToAction("Index", "Admin");

            }
            else
            {
                return RedirectToAction("Index", "Auth");
            }
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

            List<PackageCategory> packageGroup = new List<PackageCategory>()
            {
                new PackageCategory() { Package_ClassGroup_ID = "", Package_ClassGroup = "" },

                new PackageCategory() { Package_ClassGroup_ID = "1", Package_ClassGroup = "CLASS 1-7" },

                new PackageCategory() { Package_ClassGroup_ID = "2", Package_ClassGroup = "CLASS 8-12" }
            };


            ViewBag.Shared = new SelectList(boolOptionShared, "Shared_ID", "Shared_Name");
            ViewBag.EmailResult = new SelectList(boolOptionEmailDecision, "EmailDecision_ID", "EmailDecision_Name");
            ViewBag.Tests = new MultiSelectList(lstTest, "Test_Name", "Test_Name");
            ViewBag.PackageGroup = new SelectList(packageGroup, "Package_ClassGroup", "Package_ClassGroup");
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
            List<PackageCategory> packageGroup = new List<PackageCategory>()
            {
                new PackageCategory() { Package_ClassGroup_ID = "", Package_ClassGroup = "" },

                new PackageCategory() { Package_ClassGroup_ID = "1", Package_ClassGroup = "CLASS 1-7" },

                new PackageCategory() { Package_ClassGroup_ID = "2", Package_ClassGroup = "CLASS 8-12" }
            };
            ViewBag.Shared = new SelectList(boolOptionShared, "Shared_ID", "Shared_Name");
            ViewBag.EmailResult = new SelectList(boolOptionEmailDecision, "EmailDecision_ID", "EmailDecision_Name");
            ViewBag.PackageGroup = new SelectList(packageGroup, "Package_ClassGroup", "Package_ClassGroup");
            return View("Create");
        }

        //[HttpPost]
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

            List<PackageCategory> packageGroup = new List<PackageCategory>()
            {
                new PackageCategory() { Package_ClassGroup_ID = "", Package_ClassGroup = "" },

                new PackageCategory() { Package_ClassGroup_ID = "1", Package_ClassGroup = "CLASS 1-7" },

                new PackageCategory() { Package_ClassGroup_ID = "2", Package_ClassGroup = "CLASS 8-12" }
            };
           
            ViewBag.PackageGroup = new SelectList(packageGroup, "Package_ClassGroup", "Package_ClassGroup", packages.lstPackages[0].Package_ClassGroup);

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
            List<PackageCategory> packageGroup = new List<PackageCategory>()
            {
                new PackageCategory() { Package_ClassGroup_ID = "", Package_ClassGroup = "" },

                new PackageCategory() { Package_ClassGroup_ID = "1", Package_ClassGroup = "CLASS 1-7" },

                new PackageCategory() { Package_ClassGroup_ID = "2", Package_ClassGroup = "CLASS 8-12" }
            };

            ViewBag.PackageGroup = new SelectList(packageGroup, "Package_ClassGroup", "Package_ClassGroup");
            ViewBag.Shared = new SelectList(boolOptionShared, "Shared_ID", "Shared_Name");
            ViewBag.EmailResult = new SelectList(boolOptionEmailDecision, "EmailDecision_ID", "EmailDecision_Name");
            Packages packages = new Packages();
            List<Package> lstPackages = adhyapanDB.GetPackageDetails(package.Package_ID);
            packages.lstPackages = lstPackages;

            return View("Edit", packages);
        }

        //[ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        //[Authorize]
        //public ActionResult Error()
        //{
        //    return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        //}
    }
}
