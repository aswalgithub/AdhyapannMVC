using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using System.Web.Mvc;
using Adhyapann_Project.Models;
using DataAccessLayer;

using System.Text;
using GemBox.Spreadsheet;
using GemBox.Spreadsheet.Charts;
using GemBox.Document;
using Spire.Xls;
using Spire.Pdf;
using SendGrid;
using SendGrid.Helpers.Mail;

using System.IO;


namespace Adhyapan_Project.Controllers
{

    public class StudentController : Controller
    {

        public AdhyapanDB adhyapanDB = new AdhyapanDB();
        //public StudentController( AdhyapanDB adhyapanDB)
        //{

        //    this.adhyapanDB = adhyapanDB;
        //}
        public ActionResult Index()
        {
            return View();
        }



        public ActionResult SubTest(int id)
        {
            //AdhyapanDB adhyapanDB = new AdhyapanDB();
            List<Question> lstQuestion = adhyapanDB.GetSetQuestions(id);
            Questions questions = new Questions();
            questions.lstQuestion = lstQuestion;
            return View("SubTest", questions);
        }

        public ActionResult PracticeSet(int id)
        {
            //AdhyapanDB adhyapanDB = new AdhyapanDB();
            List<Question> lstQuestion = adhyapanDB.GetPracticeQuestions(id);
            Questions questions = new Questions();
            questions.lstQuestion = lstQuestion;
            return View("PracticeSet", questions);
        }

        public ActionResult SubmitQuestions(Question questions)
        {
            Questions subquestions = new Questions();


            return View("Index");
        }


        public ActionResult Register(int packageID)
        {
            //AdhyapanDB adhyapanDB = new AdhyapanDB();
            List<Package> lstPackages = adhyapanDB.GetPackageDetails(packageID);

            return View("Register", lstPackages[0]);
        }
        [HttpPost]
        public ActionResult SaveStudentDetails(Student student, string Package_Pwd, string Password)
        {

            Student studentUpdated = adhyapanDB.InsertStudentDetails(student);
            Session["Reference_Code"] = studentUpdated.Reference_Code;
            //HttpContext.Session.Set("Reference_Code", Encoding.UTF8.GetBytes((studentUpdated.Reference_Code)));           
            return RedirectToAction("LoadVerbalnformationTest", "Test");

        }


        public ActionResult Home()
        {
            //AdhyapanDB adhyapanDB = new AdhyapanDB();
            List<Package> lstPackages = adhyapanDB.GetPackageDetails();
            Packages packages = new Packages();
            packages.lstPackages = lstPackages;


            return View("Home", packages);
        }

        public ActionResult Comprehension()
        {
            return View();
        }

        public ActionResult Arithmetic()
        {
            return View();
        }

        public ActionResult Similarities()
        {
            return View();
        }

        public ActionResult Information()
        {
            return View();
        }

        public ActionResult Vocabulary()
        {
            return View();
        }

        //[ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        //public ActionResult Error()
        //{
        //    return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        //}
    }
}
