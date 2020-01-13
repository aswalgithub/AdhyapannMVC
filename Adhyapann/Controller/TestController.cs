using System;
using System.Collections.Generic;
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
using FreeLimitReachedAction = GemBox.Spreadsheet.FreeLimitReachedAction;
using System.Configuration;

namespace Adhyapann_Project.Controllers
{
    public class TestController : Controller
    {
        public AdhyapanDB adhyapanDB = new AdhyapanDB();

        public ActionResult Index()
        {
            return View();
        }

        //public TestController(AdhyapanDB adhyapanDB)
        //{
        //   this.adhyapanDB = adhyapanDB;
        //}


      

        public async Task Execute(string ref_code, StudentTestInfo studentTestInfo)
        {
            try
            {
                byte[] AsBytes = System.IO.File.ReadAllBytes(System.Web.Hosting.HostingEnvironment.MapPath("~/wwwroot/pdf/Results" + studentTestInfo.Student_TestID + ".pdf"));
                String AsBase64String = Convert.ToBase64String(AsBytes);

                //byte[] AsBytes_xls = System.IO.File.ReadAllBytes("./wwwroot/pdf/Chart" + ref_code.ToString() + ".xlsx");
                //String AsBase64String_xls = Convert.ToBase64String(AsBytes_xls);
                List<Package> lstPackages = adhyapanDB.GetPackageDetails(studentTestInfo.Package_ID);
                List<EmailAddress> emails = new List<EmailAddress>();
                if (lstPackages[0].Email_Result_ToUser == true)
                {
                    emails.Add(new EmailAddress(studentTestInfo.Email_ID));
                    emails.Add(new EmailAddress("aniketdepp@gmail.com"));
                    emails.Add(new EmailAddress("manishc56@gmail.com"));
                    //    var emails = new List<EmailAddress>
                    //{
                    //    new EmailAddress(studentTestInfo.Email_ID),
                    //    new EmailAddress("aniketdepp@gmail.com"),
                    //     new EmailAddress("manishc56@gmail.com")
                    //};
                }
                else
                {
                    emails.Add(new EmailAddress("aniketdepp@gmail.com"));
                    emails.Add(new EmailAddress("manishc56@gmail.com"));
                }
                var apiKey = ConfigurationManager.AppSettings["SENDGRID_API_KEY"].ToString();
                
                var client = new SendGridClient(apiKey);
                var from = new EmailAddress("aniketdepp@outlook.com", "Adhyapann Quiz");
                var subject = "Quiz Results for " + studentTestInfo.Name;
                //var to = new EmailAddress("aniketdepp@gmail.com", "Example User");
                var plainTextContent = "Please find attached the file with Quiz Results";
                var htmlContent = "<strong>Please find attached the file with Quiz Results</strong>";
                //var msg = MailHelper.CreateSingleEmail(from, to, subject, plainTextContent, htmlContent);
                var msg = MailHelper.CreateSingleEmailToMultipleRecipients(from, emails, subject, plainTextContent, htmlContent);

                //Attachment attachment = new Attachment();
                //attachment.Filename = "Chart.xlsx";
                //attachment.ContentId = "Chart";
                //attachment.Disposition = "attachment";
                //attachment.Content = AsBase64String_xls.ToString();

                Attachment pdfAttachment = new Attachment();
                pdfAttachment.Filename = "Results.pdf";
                pdfAttachment.ContentId = "Results";
                pdfAttachment.Disposition = "attachment";
                pdfAttachment.Content = AsBase64String.ToString();


                msg.AddAttachment(pdfAttachment);
                //msg.AddAttachment(attachment);
                var response = await client.SendEmailAsync(msg).ConfigureAwait(false);


            }
            catch (Exception ex)
            {
                Console.Write(ex.Message);
            }

        }


        public void CreateExcel(string ref_code)
        {
            
                ////AdhyapanDB adhyapanDB = new AdhyapanDB();
                StudentTestInfo studentTestScore = adhyapanDB.GetScores(ref_code);

                SpreadsheetInfo.SetLicense("FREE-LIMITED-KEY");
                SpreadsheetInfo.FreeLimitReached += (sender, e) => e.FreeLimitReachedAction = FreeLimitReachedAction.ContinueAsTrial;

                //var workbook = new ExcelFile();
                //string fileName = "ich_will.mp3";
                //string path = Path.Combine(Environment.CurrentDirectory, @"wwwroot\", "ReportTemplate.xlsx");
                //var worksheet = workbook.Worksheets.Add("Chart");
                var workbook = ExcelFile.Load(System.Web.Hosting.HostingEnvironment.MapPath("~/wwwroot/ReportTemplate.xlsx"));
                //var workbook = ExcelFile.Load(Path.Combine(System.AppDomain.CurrentDomain.BaseDirectory, @"wwwroot\", "ReportTemplate.xlsx"));

                
                var worksheet = workbook.Worksheets[0];
                //Data for Emotional Regulation Score
                worksheet.Cells["C10"].Value = studentTestScore.Name;
                worksheet.Cells["C12"].Value = studentTestScore.Age;
                worksheet.Cells["C14"].Value = studentTestScore.Email_ID;
                worksheet.Cells["C16"].Value = studentTestScore.Gender;
                worksheet.Cells["C18"].Value = studentTestScore.School_Name;
                worksheet.Cells["C20"].Value = studentTestScore.TestDate;
                worksheet.Cells["B68"].Value = "Emotional Parameters";
                worksheet.Cells["B69"].Value = "Self-Blame";
                worksheet.Cells["B70"].Value = "Acceptance";
                worksheet.Cells["B71"].Value = "Rumination";
                worksheet.Cells["B72"].Value = "Positive Refocusing";
                worksheet.Cells["B73"].Value = "Refocus on Planning";
                worksheet.Cells["B74"].Value = "Positive Reappraisal";
                worksheet.Cells["B75"].Value = "Putting into Perspective";
                worksheet.Cells["B76"].Value = "Catastrophizing";
                worksheet.Cells["B77"].Value = "Other_Blame";

                worksheet.Cells["C68"].Value = "Your Score";
                worksheet.Cells["C69"].Value = studentTestScore.ER_Self_Blame;
                worksheet.Cells["C70"].Value = studentTestScore.ER_Acceptance;
                worksheet.Cells["C71"].Value = studentTestScore.ER_Rumination;
                worksheet.Cells["C72"].Value = studentTestScore.ER_PositiveRefocusing;
                worksheet.Cells["C73"].Value = studentTestScore.ER_RefocusonPlanning;
                worksheet.Cells["C74"].Value = studentTestScore.ER_PositiveReappraisal;
                worksheet.Cells["C75"].Value = studentTestScore.ER_PuttingintoPerspective;
                worksheet.Cells["C76"].Value = studentTestScore.ER_Catastrophizing;
                worksheet.Cells["C77"].Value = studentTestScore.ER_Other_blame;

                worksheet.Cells["D68"].Value = "Average";
                worksheet.Cells["D69"].Value = 7.0;
                worksheet.Cells["D70"].Value = 8.5;
                worksheet.Cells["D71"].Value = 7.5;
                worksheet.Cells["D72"].Value = 9.5;
                worksheet.Cells["D73"].Value = 9.5;
                worksheet.Cells["D74"].Value = 10.1;
                worksheet.Cells["D75"].Value = 9.5;
                worksheet.Cells["D76"].Value = 6.0;
                worksheet.Cells["D77"].Value = 6.5;

                //chart for Emotional Regulation
                var emotional_chart = worksheet.Charts.Add(GemBox.Spreadsheet.Charts.ChartType.Column, "B68", "H88");
                emotional_chart.SelectData(worksheet.Cells.GetSubrange("B68", "D77"), true);
                emotional_chart.DataLabels.Show();
                emotional_chart.Title.Text = "Emotional Regulation";
                emotional_chart.Legend.IsVisible = true;
                emotional_chart.Legend.Position = ChartLegendPosition.Bottom;


                //Data for Verbal Score
                worksheet.Cells["B177"].Value = "Verbal Subtest Scores";
                worksheet.Cells["B178"].Value = "Information";
                worksheet.Cells["B179"].Value = "Comprehension";
                worksheet.Cells["B180"].Value = "Arithmetic";
                worksheet.Cells["B181"].Value = "Similarities";
                worksheet.Cells["B182"].Value = "Vocabulary";

                worksheet.Cells["C177"].Value = "Your Score";
                worksheet.Cells["C178"].Value = studentTestScore.Verbal_Scaled_INF;
                worksheet.Cells["C179"].Value = studentTestScore.Verbal_Scaled_COM;
                worksheet.Cells["C180"].Value = studentTestScore.Verbal_Scaled_ARI;
                worksheet.Cells["C181"].Value = studentTestScore.Verbal_Scaled_SIM;
                worksheet.Cells["C182"].Value = studentTestScore.Verbal_Scaled_VOC;

                worksheet.Cells["D177"].Value = "Average";
                worksheet.Cells["D178"].Value = 50;
                worksheet.Cells["D179"].Value = 50;
                worksheet.Cells["D180"].Value = 50;
                worksheet.Cells["D181"].Value = 50;
                worksheet.Cells["D182"].Value = 50;

                //chart for Verbal Score
                var verbal_chart = worksheet.Charts.Add(GemBox.Spreadsheet.Charts.ChartType.Column, "B177", "H189");
                verbal_chart.SelectData(worksheet.Cells.GetSubrange("B177", "D182"), true);
                verbal_chart.DataLabels.Show();
                verbal_chart.Title.Text = "Verbal Scores";
                verbal_chart.Legend.IsVisible = true;
                verbal_chart.Legend.Position = ChartLegendPosition.Bottom;


                //Data for Performance Score
                worksheet.Cells["B191"].Value = "Performance Subtest Scores";
                worksheet.Cells["B192"].Value = "Digital Sympbol";
                worksheet.Cells["B193"].Value = "Picture Completion";
                worksheet.Cells["B194"].Value = "Spatial";
                worksheet.Cells["B195"].Value = "Picture Arrangement";
                worksheet.Cells["B196"].Value = "Object Assembly";

                worksheet.Cells["C191"].Value = "Your Score";
                worksheet.Cells["C192"].Value = studentTestScore.Performance_Scaled_DS;
                worksheet.Cells["C193"].Value = studentTestScore.Performance_Scaled_PC;
                worksheet.Cells["C194"].Value = studentTestScore.Performance_Scaled_SPA;
                worksheet.Cells["C195"].Value = studentTestScore.Performance_Scaled_PA;
                worksheet.Cells["C196"].Value = studentTestScore.Performance_Scaled_OA;

                worksheet.Cells["D191"].Value = "Average";
                worksheet.Cells["D192"].Value = 50;
                worksheet.Cells["D193"].Value = 50;
                worksheet.Cells["D194"].Value = 50;
                worksheet.Cells["D195"].Value = 50;
                worksheet.Cells["D196"].Value = 50;

                //chart for Performance Score
                var perf_chart = worksheet.Charts.Add(GemBox.Spreadsheet.Charts.ChartType.Column, "B191", "H203");
                perf_chart.SelectData(worksheet.Cells.GetSubrange("B191", "D196"), true);
                perf_chart.DataLabels.Show();
                perf_chart.Title.Text = "Performance Scores";
                perf_chart.Legend.IsVisible = true;
                perf_chart.Legend.Position = ChartLegendPosition.Bottom;

                //Data for IQ Score
                worksheet.Cells["B207"].Value = "IQ Scores";
                worksheet.Cells["B208"].Value = "Verbal Score";
                worksheet.Cells["B209"].Value = "Performance";
                worksheet.Cells["B210"].Value = "Full Scale Score";

                worksheet.Cells["C207"].Value = "IQ Score";
                worksheet.Cells["C208"].Value = studentTestScore.IQ_Verbal;
                worksheet.Cells["C209"].Value = studentTestScore.IQ_Perfromance;
                worksheet.Cells["C210"].Value = studentTestScore.Full_Scale_IQ;

                worksheet.Cells["D207"].Value = "Average IQ Score";
                worksheet.Cells["D208"].Value = 100;
                worksheet.Cells["D209"].Value = 100;
                worksheet.Cells["D210"].Value = 100;

                worksheet.Cells["E207"].Value = "Percentile Score";
                worksheet.Cells["E208"].Value = studentTestScore.Percentile_Verbal;
                worksheet.Cells["E209"].Value = studentTestScore.Percentile_Performance;
                worksheet.Cells["E210"].Value = studentTestScore.Full_Percentile;

                //chart for IQ Score
                var IQ_chart = worksheet.Charts.Add(GemBox.Spreadsheet.Charts.ChartType.Column, "B207", "H221");
                IQ_chart.SelectData(worksheet.Cells.GetSubrange("B207", "E210"), true);
                IQ_chart.DataLabels.Show();
                IQ_chart.Title.Text = "Your IQ Scores";
                IQ_chart.Legend.IsVisible = true;
                IQ_chart.Legend.Position = ChartLegendPosition.Bottom;

                // Make entire sheet print on a single page.
                //worksheet.PrintOptions.FitWorksheetWidthToPages = 1;
                workbook.Save(System.Web.Hosting.HostingEnvironment.MapPath("~/wwwroot/pdf/Chart" + studentTestScore.Student_TestID + ".xlsx"));
                //workbook.Save(Path.Combine(System.AppDomain.CurrentDomain.BaseDirectory, @"wwwroot\pdf\", "Chart" + ref_code.ToString() + ".xlsx"));
                //workbook.Save("./wwwroot/pdf/Chart" + ref_code.ToString() + ".xlsx");

                                             
                Spire.Xls.Workbook pdfWorkbook = new Spire.Xls.Workbook();
                pdfWorkbook.LoadFromFile(System.Web.Hosting.HostingEnvironment.MapPath("~/wwwroot/pdf/Chart" + studentTestScore.Student_TestID + ".xlsx"));
                
                pdfWorkbook.SaveToFile(System.Web.Hosting.HostingEnvironment.MapPath("~/wwwroot/pdf/Results" + studentTestScore.Student_TestID + ".pdf"), Spire.Xls.FileFormat.PDF);
               
                Execute(ref_code, studentTestScore).Wait();
                if ((System.IO.File.Exists(System.Web.Hosting.HostingEnvironment.MapPath("~/wwwroot/pdf/Chart" + studentTestScore.Student_TestID + ".xlsx"))))
                {
                    System.IO.File.Delete(System.Web.Hosting.HostingEnvironment.MapPath("~/wwwroot/pdf/Chart" + studentTestScore.Student_TestID + ".xlsx"));
                }
                if ((System.IO.File.Exists(System.Web.Hosting.HostingEnvironment.MapPath("~/wwwroot/pdf/Results" + studentTestScore.Student_TestID + ".pdf")))) 
                {
                    System.IO.File.Delete(System.Web.Hosting.HostingEnvironment.MapPath("~/wwwroot/pdf/Results" + studentTestScore.Student_TestID + ".pdf"));
                }
          
        }
            



        public string SetIQPercentile(string ref_code)
        {
            string status = String.Empty;
            int verbal_total_score;
            int performance_total_score;
            int total_score;

            //AdhyapanDB adhyapanDB = new AdhyapanDB();
            StudentTestInfo studentTestScore = adhyapanDB.GetScores(ref_code);
            List<ScaledScoreMapping> scaledScoreMapping = adhyapanDB.GetScaledScoreMapping(studentTestScore.Age);
            int Verbal_INF_Scaled = studentTestScore.Verbal_INF == 0 ? 0 : scaledScoreMapping.Where(x => x.Verbal_INF <= studentTestScore.Verbal_INF).OrderByDescending(y => y.Verbal_INF).FirstOrDefault().Verbal_Scaled_Score;
            int Verbal_COM_Scaled = studentTestScore.Verbal_COM == 0 ? 0 : scaledScoreMapping.Where(x => x.Verbal_COM <= studentTestScore.Verbal_COM).OrderByDescending(y => y.Verbal_COM).FirstOrDefault().Verbal_Scaled_Score;
            int Verbal_ARI_Scaled = studentTestScore.Verbal_ARI == 0 ? 0 : scaledScoreMapping.Where(x => x.Verbal_ARI <= studentTestScore.Verbal_ARI).OrderByDescending(y => y.Verbal_ARI).FirstOrDefault().Verbal_Scaled_Score;
            int Verbal_SIM_Scaled = studentTestScore.Verbal_SIM == 0 ? 0 : scaledScoreMapping.Where(x => x.Verbal_SIM <= studentTestScore.Verbal_SIM).OrderByDescending(y => y.Verbal_SIM).FirstOrDefault().Verbal_Scaled_Score;
            int Verbal_VOC_Scaled = studentTestScore.Verbal_VOC == 0 ? 0 : scaledScoreMapping.Where(x => x.Verbal_VOC <= studentTestScore.Verbal_VOC).OrderByDescending(y => y.Verbal_VOC).FirstOrDefault().Verbal_Scaled_Score;
            int Performance_DS_Scaled = studentTestScore.Performance_DS == 0 ? 0 : scaledScoreMapping.Where(x => x.Performance_DS <= studentTestScore.Performance_DS).OrderByDescending(y => y.Performance_DS).FirstOrDefault().Performance_Scaled_Score;
            int Performance_OA_Scaled = studentTestScore.Performance_OA == 0 ? 0 : scaledScoreMapping.Where(x => x.Performance_OA <= studentTestScore.Performance_OA).OrderByDescending(y => y.Performance_OA).FirstOrDefault().Performance_Scaled_Score;
            int Performance_PA_Scaled = studentTestScore.Performance_PA == 0 ? 0 : scaledScoreMapping.Where(x => x.Performance_PA <= studentTestScore.Performance_PA).OrderByDescending(y => y.Performance_PA).FirstOrDefault().Performance_Scaled_Score;
            int Performance_PC_Scaled = studentTestScore.Performance_PC == 0 ? 0 : scaledScoreMapping.Where(x => x.Performance_PC <= studentTestScore.Performance_PC).OrderByDescending(y => y.Performance_PC).FirstOrDefault().Performance_Scaled_Score;
            int Performance_SPA_Scaled = studentTestScore.Performance_SPA == 0 ? 0 : scaledScoreMapping.Where(x => x.Performance_SPA <= studentTestScore.Performance_SPA).OrderByDescending(y => y.Performance_SPA).FirstOrDefault().Performance_Scaled_Score;


            verbal_total_score = Verbal_INF_Scaled + Verbal_COM_Scaled + Verbal_ARI_Scaled + Verbal_SIM_Scaled + Verbal_VOC_Scaled;
            performance_total_score = Performance_DS_Scaled + Performance_OA_Scaled + Performance_PA_Scaled + Performance_PC_Scaled + Performance_SPA_Scaled;
            total_score = verbal_total_score + performance_total_score;

            List<IQandPercentileMapping> qandPercentilesMapping = adhyapanDB.GetIQandPercentileMapping(studentTestScore.Age);
            var minTotalScaledverbalScore = qandPercentilesMapping.Min(r => r.Total_Scaled_Verbal_Score);
            var minTotalScaledperformanceScore = qandPercentilesMapping.Min(r => r.Total_Scaled_Performance_Score);
            var minFullScore = qandPercentilesMapping.Min(r => r.Full_Score);
            int Scaled_Verbal_Score_IQ = verbal_total_score< minTotalScaledverbalScore? qandPercentilesMapping.Where(x => x.Total_Scaled_Verbal_Score == minTotalScaledverbalScore).FirstOrDefault().Scaled_Verbal_Score_IQ : qandPercentilesMapping.Where(x => x.Total_Scaled_Verbal_Score <= verbal_total_score).OrderByDescending(y => y.Total_Scaled_Verbal_Score).FirstOrDefault().Scaled_Verbal_Score_IQ;
            int Scaled_Verbal_Score_Percentile = verbal_total_score < minTotalScaledverbalScore ? qandPercentilesMapping.Where(x => x.Total_Scaled_Verbal_Score == minTotalScaledverbalScore).FirstOrDefault().Scaled_Verbal_Score_Percentile : qandPercentilesMapping.Where(x => x.Total_Scaled_Verbal_Score <= verbal_total_score).OrderByDescending(y => y.Total_Scaled_Verbal_Score).FirstOrDefault().Scaled_Verbal_Score_Percentile;
            int Scaled_Performance_Score_IQ = performance_total_score< minTotalScaledperformanceScore? qandPercentilesMapping.Where(x => x.Total_Scaled_Performance_Score == minTotalScaledperformanceScore).FirstOrDefault().Scaled_Performance_Score_IQ : qandPercentilesMapping.Where(x => x.Total_Scaled_Performance_Score <= performance_total_score).OrderByDescending(y => y.Total_Scaled_Performance_Score).FirstOrDefault().Scaled_Performance_Score_IQ;
            int Scaled_Performance_Score_Percentile = performance_total_score < minTotalScaledperformanceScore ? qandPercentilesMapping.Where(x => x.Total_Scaled_Performance_Score == minTotalScaledperformanceScore).FirstOrDefault().Scaled_Performance_Score_Percentile : qandPercentilesMapping.Where(x => x.Total_Scaled_Performance_Score <= performance_total_score).OrderByDescending(y => y.Total_Scaled_Performance_Score).FirstOrDefault().Scaled_Performance_Score_Percentile;
            int Full_Score_IQ = total_score< minFullScore? qandPercentilesMapping.Where(x => x.Full_Score == minFullScore).FirstOrDefault().Full_Score_IQ : qandPercentilesMapping.Where(x => x.Full_Score <= total_score).OrderByDescending(y => y.Full_Score).FirstOrDefault().Full_Score_IQ;
            int Full_Score_Percentile = total_score < minFullScore ? qandPercentilesMapping.Where(x => x.Full_Score == minFullScore).FirstOrDefault().Full_Score_Percentile : qandPercentilesMapping.Where(x => x.Full_Score <= total_score).OrderByDescending(y => y.Full_Score).FirstOrDefault().Full_Score_Percentile;

            status = adhyapanDB.SetScores(ref_code, Verbal_INF_Scaled, Verbal_COM_Scaled, Verbal_ARI_Scaled, Verbal_SIM_Scaled, Verbal_VOC_Scaled, Performance_DS_Scaled, Performance_PC_Scaled, Performance_SPA_Scaled, Performance_PA_Scaled, Performance_OA_Scaled, verbal_total_score, performance_total_score, total_score, Scaled_Verbal_Score_IQ, Scaled_Verbal_Score_Percentile, Scaled_Performance_Score_IQ, Scaled_Performance_Score_Percentile, Full_Score_IQ, Full_Score_Percentile);

            return status;
        }

        public ActionResult LoadVerbalnformationTest()
        {
            //HttpContext.Session.TryGetValue("Reference_Code", out byte[] Reference_Code_Byte);
            if (Session["Reference_Code"] != null)
            {
                string reference_Code = Session["Reference_Code"].ToString();
                //string reference_Code = Encoding.UTF8.GetString(Reference_Code_Byte);
                //AdhyapanDB adhyapanDB = new AdhyapanDB();
                Student studentDetail = adhyapanDB.GetStudentDetails(reference_Code);
                return View("Information", studentDetail);
            }
            else
                return RedirectToAction("Home", "Student");

        }

        public ActionResult Information()
        {
            //AdhyapanDB adhyapanDB = new AdhyapanDB();
            Student studentDetail = adhyapanDB.GetStudentDetails("+wfgObHKh0KqCylk7IA7SA==");

            return View("Comprehension", studentDetail);
        }

        public ActionResult DigitalSymbol()
        {
            return View("DigitalSymbol");
        }

        public ActionResult PictureCompletion()
        {
            //AdhyapanDB adhyapanDB = new AdhyapanDB();
            Student studentDetail = adhyapanDB.GetStudentDetails("YL6VUvotUkieaKzEeUoV8g==");
            return View("PictureCompletion", studentDetail);
        }
        public ActionResult Spatial()
        {
            return View("Spatial");
        }

        public ActionResult PictureArrangement()
        {
            return View("PictureArrangement");
        }

        public ActionResult PictureAssembly()
        {
            return View("PictureAssembly");
        }

        public ActionResult EmotionalRegulation912()
        {
            //AdhyapanDB adhyapanDB = new AdhyapanDB();
            Student studentDetail = adhyapanDB.GetStudentDetails("6LV1mDEI3Um43GyEqSTOOg==");

            return View("EmotionalRegulation9-12", studentDetail);
        }

        public ActionResult PDFTest()
        {
            CreateExcel("1MOjrR1wbkuVSBmCe4xNag==");
            return View("PictureAssembly");
        }

        public ActionResult SaveInformationTest(VAInformationInput informationTestInput)
        {
            //AdhyapanDB adhyapanDB = new AdhyapanDB();
            List<TestAnswerMapping> lstTestAnswers = adhyapanDB.GetTestAnswersDetails("VAInformation");

            int testScore = GetTestScore(informationTestInput, lstTestAnswers, "VAInformation");

            adhyapanDB.UpdateTestScore(testScore, "Verbal_INF", informationTestInput.Reference_Code);

            //string reference_Code = Encoding.UTF8.GetString(Reference_Code_Byte);          
            Student studentDetail = adhyapanDB.GetStudentDetails(informationTestInput.Reference_Code);

            return View("Comprehension", studentDetail);
        }

        public ActionResult SaveComprehensionTest(VAComprehensionInput comprehensionTestInput)
        {
            //AdhyapanDB adhyapanDB = new AdhyapanDB();
            List<TestAnswerMapping> lstTestAnswers = adhyapanDB.GetTestAnswersDetails("VAComprehension");

            int testScore = GetTestScore(comprehensionTestInput, lstTestAnswers, "VAComprehension");

            adhyapanDB.UpdateTestScore(testScore, "Verbal_COM", comprehensionTestInput.Reference_Code);

            Student studentDetail = adhyapanDB.GetStudentDetails(comprehensionTestInput.Reference_Code);

            return View("Arithmetic", studentDetail);
        }

        public ActionResult SaveArithmaticTest(VAArithmeticInput arithmeticTestInput)
        {
            //AdhyapanDB adhyapanDB = new AdhyapanDB();
            List<TestAnswerMapping> lstTestAnswers = adhyapanDB.GetTestAnswersDetails("VAArithmetic");

            int testScore = GetTestScore(arithmeticTestInput, lstTestAnswers, "VAArithmetic");

            adhyapanDB.UpdateTestScore(testScore, "Verbal_ARI", arithmeticTestInput.Reference_Code);

            Student studentDetail = adhyapanDB.GetStudentDetails(arithmeticTestInput.Reference_Code);

            return View("Similarities", studentDetail);
        }

        public ActionResult SaveSimilaritiesTest(VASimilarityInput similarityTestInput)
        {
            //AdhyapanDB adhyapanDB = new AdhyapanDB();
            List<TestAnswerMapping> lstTestAnswers = adhyapanDB.GetTestAnswersDetails("VASimilarity");

            int testScore = GetTestScore(similarityTestInput, lstTestAnswers, "VASimilarity");

            adhyapanDB.UpdateTestScore(testScore, "Verbal_SIM", similarityTestInput.Reference_Code);

            Student studentDetail = adhyapanDB.GetStudentDetails(similarityTestInput.Reference_Code);

            return View("Vocabulary", studentDetail);
        }

        public ActionResult SaveVocabTest(VAVocabInput vocabTestInput)
        {
            //AdhyapanDB adhyapanDB = new AdhyapanDB();
            List<TestAnswerMapping> lstTestAnswers = adhyapanDB.GetTestAnswersDetails("VAVocab");

            int testScore = GetTestScore(vocabTestInput, lstTestAnswers, "VAVocab");

            adhyapanDB.UpdateTestScore(testScore, "Verbal_VOC", vocabTestInput.Reference_Code);
            Student studentDetail = adhyapanDB.GetStudentDetails(vocabTestInput.Reference_Code);

            return View("DigitalSymbol", studentDetail);
        }
        public ActionResult SubmitDigitalSymbolTest(DigitalSymbolnput digitalSymbolnput)
        {
            //AdhyapanDB adhyapanDB = new AdhyapanDB();
            List<TestAnswerMapping> lstTestAnswers = adhyapanDB.GetTestAnswersDetails("PADigitalSymbol");

            int testScore = GetTestScore(digitalSymbolnput, lstTestAnswers, "PADigitalSymbol");

            adhyapanDB.UpdateTestScore(testScore, "Performance_DS", digitalSymbolnput.Reference_Code);
            Student studentDetail = adhyapanDB.GetStudentDetails(digitalSymbolnput.Reference_Code);

            return View("PictureCompletion", studentDetail);
        }

        public ActionResult SavePictureCompletionTest(PAPictureCompletionInput pictureCompletionInput)
        {
            //AdhyapanDB adhyapanDB = new AdhyapanDB();
            List<TestAnswerMapping> lstTestAnswers = adhyapanDB.GetTestAnswersDetails("PAPictureCompletion");

            int testScore = GetTestScore(pictureCompletionInput, lstTestAnswers, "PAPictureCompletion");

            adhyapanDB.UpdateTestScore(testScore, "Performance_PC", pictureCompletionInput.Reference_Code);

            Student studentDetail = adhyapanDB.GetStudentDetails(pictureCompletionInput.Reference_Code);

            return View("Spatial", studentDetail);
        }

        public ActionResult SaveSpatialTest(PASpatialInput spatialInput)
        {
            //AdhyapanDB adhyapanDB = new AdhyapanDB();
            List<TestAnswerMapping> lstTestAnswers = adhyapanDB.GetTestAnswersDetails("PASpatial");

            int testScore = GetTestScore(spatialInput, lstTestAnswers, "PASpatial");

            adhyapanDB.UpdateTestScore(testScore, "Performance_SPA", spatialInput.Reference_Code);
            Student studentDetail = adhyapanDB.GetStudentDetails(spatialInput.Reference_Code);

            return View("PictureArrangement", studentDetail);
        }

        public ActionResult SavePictureArrangementTest(PAPicArrInput picArrInput)
        {
            //AdhyapanDB adhyapanDB = new AdhyapanDB();
            List<TestAnswerMapping> lstTestAnswers = adhyapanDB.GetTestAnswersDetails("PAPicArr");

            int testScore = GetTestScore(picArrInput, lstTestAnswers, "PAPicArr");

            adhyapanDB.UpdateTestScore(testScore, "Performance_PA", picArrInput.Reference_Code);
            Student studentDetail = adhyapanDB.GetStudentDetails(picArrInput.Reference_Code);

            return View("PictureAssembly", studentDetail);
        }

        public ActionResult SavePictureAssemblyTest(PAPicAssemInput picAssemInput)
        {
            //AdhyapanDB adhyapanDB = new AdhyapanDB();
            List<TestAnswerMapping> lstTestAnswers = adhyapanDB.GetTestAnswersDetails("PAPicAssem");

            int testScore = GetTestScore(picAssemInput, lstTestAnswers, "PAPicAssem");

            adhyapanDB.UpdateTestScore(testScore, "Performance_OA", picAssemInput.Reference_Code);
            Student studentDetail = adhyapanDB.GetStudentDetails(picAssemInput.Reference_Code);

            return View("EmotionalRegulation9-12", studentDetail);
        }

        public ActionResult SaveEmotionalRegulationSenior(EmotionaRegInput emotionaRegInput)
        {
            //AdhyapanDB adhyapanDB = new AdhyapanDB();

            int ER_Self_Blame = emotionaRegInput.SeniorER1 + emotionaRegInput.SeniorER10 + emotionaRegInput.SeniorER19 + emotionaRegInput.SeniorER28;
            int ER_Acceptance = emotionaRegInput.SeniorER2 + emotionaRegInput.SeniorER11 + emotionaRegInput.SeniorER20 + emotionaRegInput.SeniorER29;
            int ER_Rumination = emotionaRegInput.SeniorER3 + emotionaRegInput.SeniorER12 + emotionaRegInput.SeniorER21 + emotionaRegInput.SeniorER30;
            int ER_PositiveRefocusing = emotionaRegInput.SeniorER4 + emotionaRegInput.SeniorER13 + emotionaRegInput.SeniorER22 + emotionaRegInput.SeniorER31;
            int ER_RefocusonPlanning = emotionaRegInput.SeniorER5 + emotionaRegInput.SeniorER14 + emotionaRegInput.SeniorER23 + emotionaRegInput.SeniorER32;
            int ER_PositiveReappraisal = emotionaRegInput.SeniorER6 + emotionaRegInput.SeniorER15 + emotionaRegInput.SeniorER24 + emotionaRegInput.SeniorER33;
            int ER_PuttingintoPerspective = emotionaRegInput.SeniorER7 + emotionaRegInput.SeniorER16 + emotionaRegInput.SeniorER25 + emotionaRegInput.SeniorER34;
            int ER_Catastrophizing = emotionaRegInput.SeniorER8 + emotionaRegInput.SeniorER17 + emotionaRegInput.SeniorER26 + emotionaRegInput.SeniorER35;
            int ER_Other_blame = emotionaRegInput.SeniorER9 + emotionaRegInput.SeniorER18 + emotionaRegInput.SeniorER27 + emotionaRegInput.SeniorER36;

            adhyapanDB.UpdateTestScoreERSenior(emotionaRegInput.Reference_Code, ER_Self_Blame, ER_Acceptance, ER_Rumination, ER_PositiveRefocusing, ER_RefocusonPlanning, ER_PositiveReappraisal, ER_PuttingintoPerspective, ER_Catastrophizing, ER_Other_blame);

            SetIQPercentile(emotionaRegInput.Reference_Code);
            CreateExcel(emotionaRegInput.Reference_Code);
            return View("ThankYou");

        }


        public int GetTestScore(Object object1, List<TestAnswerMapping> lstTestAnswers, string questionPrefix)
        {
            //do something with the object like below 

            int count = 1;

            foreach (TestAnswerMapping testAnswerMapping in lstTestAnswers)
            {
                if (testAnswerMapping.Question == questionPrefix + Convert.ToString(count))
                    testAnswerMapping.SubmittedAnswer = object1.GetType().GetProperty(testAnswerMapping.Question).GetValue(object1) == null ? "Z" : object1.GetType().GetProperty(testAnswerMapping.Question).GetValue(object1, null).ToString();
                if (testAnswerMapping.SubmittedAnswer == testAnswerMapping.Answer)
                    testAnswerMapping.Correct = 1;

                count++;
            }
            int testScore = (from x in lstTestAnswers select x.Correct).Sum();
            return testScore;
        }
    }
}