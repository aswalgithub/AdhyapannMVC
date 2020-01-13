using System;
using System.Collections.Generic;
using System.Data;
using MySql.Data;
using System.Configuration;
using MySql.Data.MySqlClient;



namespace DataAccessLayer
{
    public class AdhyapanDB
    {
        //IConfiguration _iconfiguration;
        //public AdhyapanDB(IConfiguration iconfiguration)
        //{
        //    _iconfiguration = iconfiguration;
        //}
        public string ConnectionString { get; set; }
        private MySqlConnection GetConnection()
        {
            return new MySqlConnection(ConfigurationManager.AppSettings["ConnectionString"].ToString());
        }
        public void InsertPackage(Package package)
        {
            //string ConnectionString = @"Data source=DESKTOP-28M703K\SQLEXPRESS; Database=Adhyapann; Integrated Security=SSPI;";

            ////string ConnectionString = @"Data source=DESKTOP-28M703K\SQLEXPRESS; Database=Adhyapann; Integrated Security=SSPI;";

            // Query to be executed
            string query = "Insert Into package (Package_Name, Package_Code, Package_Password, Shared, Price, Email_Result_ToUser, AssociatedTests,Package_ClassGroup) " +
                               "VALUES (@Package_Name, @Package_Code, @Package_Password, @Shared, @Price, @Email_Result_ToUser, @AssociatedTests,@Package_ClassGroup ) ";
            
            // instance connection and command
            using (MySqlConnection cn = GetConnection())
            using (MySqlCommand cmd = new MySqlCommand(query, cn))
            {
                // add parameters and their values
                cmd.Parameters.Add("@Package_Name", MySql.Data.MySqlClient.MySqlDbType.VarChar, 255).Value = package.Package_Name;
                //cmd.Parameters.Add("@Package_URL", MySql.Data.MySqlClient.MySqlDbType.VarChar, 255).Value = package.Package_URL;
                cmd.Parameters.Add("@Package_Code", MySql.Data.MySqlClient.MySqlDbType.VarChar, 100).Value = package.Package_Code;
                cmd.Parameters.Add("@Package_Password", MySql.Data.MySqlClient.MySqlDbType.VarChar, 50).Value = package.Package_Password;
                cmd.Parameters.Add("@Shared", MySql.Data.MySqlClient.MySqlDbType.Bit).Value = package.Shared;
                cmd.Parameters.Add("@Price", MySql.Data.MySqlClient.MySqlDbType.VarChar, 10).Value = package.Price;
                cmd.Parameters.Add("@Email_Result_ToUser", MySql.Data.MySqlClient.MySqlDbType.Bit).Value = package.Email_Result_ToUser;
                cmd.Parameters.Add("@AssociatedTests", MySql.Data.MySqlClient.MySqlDbType.VarChar, 100).Value = package.AssociatedTests;
                cmd.Parameters.Add("@Package_ClassGroup", MySql.Data.MySqlClient.MySqlDbType.VarChar, 10).Value = package.Package_ClassGroup;

                // open connection, execute command and close connection
                cn.Open();
                cmd.ExecuteNonQuery();
                cn.Close();
            }
        }

        public Student InsertStudentDetails(Student student)
        {
            //string ConnectionString = @"Data source=DESKTOP-28M703K\SQLEXPRESS; Database=Adhyapann; Integrated Security=SSPI;";

            ////string ConnectionString = @"Data source=DESKTOP-28M703K\SQLEXPRESS; Database=Adhyapann; Integrated Security=SSPI;";

            //string guidResult = System.Guid.NewGuid().ToString();
            //guidResult = guidResult.Replace("-", string.Empty);
            string uniquevalue = Convert.ToBase64String(Guid.NewGuid().ToByteArray()); ;
           
            //int Age = 14;
            // Query to be executed
            string query = "Insert Into student_testinfo(Name, School_Name, Gender, Email_ID, Class, DOB, Age, Reference_Code, TestDate, Package_ID, Package_Name) " +
                               "VALUES (@Name,@School_Name,@Gender,@Email_ID,@Class,STR_TO_DATE(@DOB,'%d/%m/%Y'), TIMESTAMPDIFF(YEAR, STR_TO_DATE(@DOB, '%d/%m/%Y'), CURDATE()),@Reference_Code,@Test_Date,@Package_ID,@Package_Name) ";
            

            // instance connection and command
            using (MySqlConnection cn = GetConnection())
            using (MySqlCommand cmd = new MySqlCommand(query, cn))
            {
                // add parameters and their values
                cmd.Parameters.Add("@Name", MySql.Data.MySqlClient.MySqlDbType.VarChar, 200).Value = student.Name;
                //cmd.Parameters.Add("@Package_URL", MySql.Data.MySqlClient.MySqlDbType.VarChar, 255).Value = package.Package_URL;
                cmd.Parameters.Add("@School_Name", MySql.Data.MySqlClient.MySqlDbType.VarChar, 255).Value = student.School_Name;
                cmd.Parameters.Add("@Gender", MySql.Data.MySqlClient.MySqlDbType.VarChar, 50).Value = student.Gender == "Male" ? "M" : "F";
                cmd.Parameters.Add("@Email_ID", MySql.Data.MySqlClient.MySqlDbType.VarChar, 100).Value = student.Email_ID;
                cmd.Parameters.Add("@Class", MySql.Data.MySqlClient.MySqlDbType.VarChar, 100).Value = student.Class;            
                cmd.Parameters.Add("@DOB", MySql.Data.MySqlClient.MySqlDbType.VarChar, 12).Value = student.DOB;
               
                cmd.Parameters.Add("@Reference_Code", MySql.Data.MySqlClient.MySqlDbType.VarChar, 255).Value = uniquevalue;
                cmd.Parameters.Add("@Test_Date", MySql.Data.MySqlClient.MySqlDbType.DateTime).Value = DateTime.Now; 
                cmd.Parameters.Add("@Package_ID", MySql.Data.MySqlClient.MySqlDbType.UInt32).Value = student.Package_ID;
                cmd.Parameters.Add("@Package_Name", MySql.Data.MySqlClient.MySqlDbType.VarChar, 255).Value = student.Package_Name;


                // open connection, execute command and close connection
                cn.Open();
                cmd.ExecuteNonQuery();
                cn.Close();
            }
            student = GetStudentDetails(uniquevalue);
            return student;
        }
        public Student GetStudentDetails(string reference_code)
        {
            //string ConnectionString = @"Data source=DESKTOP-28M703K\SQLEXPRESS; Database=Adhyapann; Integrated Security=SSPI;";

            ////string ConnectionString = @"Data source=DESKTOP-28M703K\SQLEXPRESS; Database=Adhyapann; Integrated Security=SSPI;";


            // Query to be executed
            string query = "Select School_Name, Gender, Email_ID,Name, Reference_Code,Package_ID,Package_Name from student_testinfo where Reference_Code= @Reference_Code";

            // instance connection and command
            Student student = new Student();
            using (MySqlConnection cn = GetConnection())
            using (MySqlCommand cmd = new MySqlCommand(query, cn))
            {
                // add parameters and their values

                cmd.Parameters.Add("@Reference_Code", MySql.Data.MySqlClient.MySqlDbType.VarChar, 255).Value = reference_code;


                // open connection, execute command and close connection
                cn.Open();
                MySqlDataReader reader = cmd.ExecuteReader();
                while (reader.Read())
                {
                    student.Reference_Code = reader["Reference_Code"].ToString();
                    student.Email_ID = reader["Email_ID"].ToString();
                    student.Name = reader["Name"].ToString();
                    student.School_Name = reader["School_Name"].ToString();
                    student.Package_ID = Convert.ToInt32(reader["Package_ID"].ToString());
                    student.Package_Name = reader["Package_Name"].ToString();
                }

                cn.Close();
            }

            return student;
        }

        private static int CalculateAge(DateTime dateOfBirth)
        {
            int age = 0;
            age = DateTime.Now.Year - dateOfBirth.Year;
            if (DateTime.Now.DayOfYear < dateOfBirth.DayOfYear)
                age = age - 1;

            return age;
        }

        public void UpdatePackage(Package package)
        {
            //string ConnectionString = @"Data source=DESKTOP-28M703K\SQLEXPRESS; Database=Adhyapann; Integrated Security=SSPI;";



            // Query to be executed
            string query = "Update package set Package_Name=@Package_Name, Package_Code=@Package_Code, Package_Password=@Package_Password, Shared=@Shared, Price=@Price, Email_Result_ToUser=@Email_Result_ToUser, AssociatedTests=@AssociatedTests, Package_ClassGroup = @Package_ClassGroup where Package_ID= @Package_ID ";

            // instance connection and command
            using (MySqlConnection cn = GetConnection())
            using (MySqlCommand cmd = new MySqlCommand(query, cn))
            {
                // add parameters and their values
                cmd.Parameters.Add("@Package_Name", MySql.Data.MySqlClient.MySqlDbType.VarChar, 255).Value = package.Package_Name;
                //cmd.Parameters.Add("@Package_URL", MySql.Data.MySqlClient.MySqlDbType.VarChar, 255).Value = package.Package_URL;
                cmd.Parameters.Add("@Package_Code", MySql.Data.MySqlClient.MySqlDbType.VarChar, 100).Value = package.Package_Code;
                cmd.Parameters.Add("@Package_Password", MySql.Data.MySqlClient.MySqlDbType.VarChar, 50).Value = package.Package_Password;
                cmd.Parameters.Add("@Shared", MySql.Data.MySqlClient.MySqlDbType.Bit).Value = package.Shared;
                cmd.Parameters.Add("@Price", MySql.Data.MySqlClient.MySqlDbType.VarChar, 10).Value = package.Price;
                cmd.Parameters.Add("@Email_Result_ToUser", MySql.Data.MySqlClient.MySqlDbType.Bit).Value = package.Email_Result_ToUser;
                cmd.Parameters.Add("@AssociatedTests", MySql.Data.MySqlClient.MySqlDbType.VarChar, 100).Value = package.AssociatedTests;
                cmd.Parameters.Add("@Package_ID", MySql.Data.MySqlClient.MySqlDbType.UInt32).Value = package.Package_ID;
                cmd.Parameters.Add("@Package_ClassGroup", MySql.Data.MySqlClient.MySqlDbType.VarChar, 10).Value = package.Package_ClassGroup;

                // open connection, execute command and close connection
                cn.Open();
                cmd.ExecuteNonQuery();
                cn.Close();
            }
        }

        public void DeletePackage(int id)
        {
            //string ConnectionString = @"Data source=DESKTOP-28M703K\SQLEXPRESS; Database=Adhyapann; Integrated Security=SSPI;";



            // Query to be executed
            string query = "Delete from package where Package_ID = @id ";


            // instance connection and command
            using (MySqlConnection cn = GetConnection())
            using (MySqlCommand cmd = new MySqlCommand(query, cn))
            {
                // add parameters and their values
                cmd.Parameters.Add("@id", MySql.Data.MySqlClient.MySqlDbType.UInt32).Value = id;
                //cmd.Parameters.Add("@Package_URL", MySql.Data.MySqlClient.MySqlDbType.VarChar, 255).Value = package.Package_URL;


                // open connection, execute command and close connection
                cn.Open();
                cmd.ExecuteNonQuery();
                cn.Close();
            }
        }



        public void UpdatePackage(int Package_ID, string Package_Name, string Package_URL, string Package_Code, string Package_Password, bool Shared, string Price, bool Email_Result_ToUser, string AssociatedTests)
        {
            //string ConnectionString = @"Data source=DESKTOP-28M703K\SQLEXPRESS; Database=Adhyapann; Integrated Security=SSPI;";

            // Collecting Values


            // Query to be executed
            string query = "Update package Set Package_Name=@Package_Name, Package_Code= @Package_Code, Package_Password=@Package_Password, Shared=@Shared, Price=@Price, Email_Result_ToUser=@Email_Result_ToUser, AssociatedTests=@AssociatedTests where Package_ID = @Package_ID " +
                               "VALUES ( @Package_URL, , , , , , ) ";

            // instance connection and command
            using (MySqlConnection cn = GetConnection())
            using (MySqlCommand cmd = new MySqlCommand(query, cn))
            {
                // add parameters and their values
                cmd.Parameters.Add("@Package_Name", MySql.Data.MySqlClient.MySqlDbType.VarChar, 255).Value = Package_Name;
                cmd.Parameters.Add("@Package_Code", MySql.Data.MySqlClient.MySqlDbType.VarChar, 100).Value = Package_Code;
                cmd.Parameters.Add("@Package_Password", MySql.Data.MySqlClient.MySqlDbType.VarChar, 50).Value = Package_Password;
                cmd.Parameters.Add("@Shared", MySql.Data.MySqlClient.MySqlDbType.Bit).Value = Shared;
                cmd.Parameters.Add("@Price", MySql.Data.MySqlClient.MySqlDbType.VarChar, 10).Value = Price;
                cmd.Parameters.Add("@Email_Result_ToUser", MySql.Data.MySqlClient.MySqlDbType.Bit).Value = Email_Result_ToUser;
                cmd.Parameters.Add("@AssociatedTests", MySql.Data.MySqlClient.MySqlDbType.VarChar, 100).Value = AssociatedTests;
                cmd.Parameters.Add("@PackageID", MySql.Data.MySqlClient.MySqlDbType.UInt32).Value = Package_ID;

                // open connection, execute command and close connection
                cn.Open();
                cmd.ExecuteNonQuery();
                cn.Close();
            }
        }


        public List<Package> GetPackageDetails()
        {
            //string ConnectionString = @"Data source=DESKTOP-28M703K\SQLEXPRESS; Database=Adhyapann; Integrated Security=SSPI;";

            // Collecting Values           
            List<Package> lstPackage = new List<Package>();
            // Query to be executed
            string query = "Select Package_ID, Package_Name, Package_URL,Package_Code,Package_Password, Shared, Price ,	Email_Result_ToUser, AssociatedTests,Completed ,Attended, ImagePath, Package_ClassGroup from package ";

            // instance connection and command
            using (MySqlConnection cn = GetConnection())
            {
                using (MySqlCommand cmd = new MySqlCommand(query, cn))
                {
                    // open connection, execute command and close connection
                    cn.Open();
                    MySqlDataReader reader = cmd.ExecuteReader();


                    while (reader.Read())
                    {
                        Package package = new Package();
                        package.Package_ID = int.Parse(reader["Package_ID"].ToString());
                        package.Package_Name = reader["Package_Name"].ToString();
                        package.Package_Code = reader["Package_Code"].ToString();
                        package.Package_Password = reader["Package_Password"].ToString();
                        package.Package_URL = reader["Package_URL"].ToString();
                        package.Price = reader["Price"].ToString();
                        package.Shared = Convert.ToBoolean(reader["Shared"].ToString());
                        package.Email_Result_ToUser = Convert.ToBoolean(reader["Email_Result_ToUser"].ToString());
                        package.AssociatedTests = reader["AssociatedTests"].ToString();
                        package.ImagePath = reader["ImagePath"].ToString();
                        package.Package_ClassGroup = reader["Package_ClassGroup"].ToString();
                        lstPackage.Add(package);
                    }

                    cn.Close();
                }
            }
            return lstPackage;
        }

        public List<Package> GetPackageDetails(int package_ID)
        {
            //string ConnectionString = @"Data source=DESKTOP-28M703K\SQLEXPRESS; Database=Adhyapann; Integrated Security=SSPI;";

            // Collecting Values           
            List<Package> lstPackage = new List<Package>();
            // Query to be executed
            string query = "Select Package_ID, Package_Name, Package_URL,Package_Code,Package_Password, Shared, Price ,	Email_Result_ToUser, AssociatedTests,Completed ,Attended, ImagePath, Package_ClassGroup from package where Package_ID = @id ";

            // instance connection and command
            using (MySqlConnection cn = GetConnection())
            {
                using (MySqlCommand cmd = new MySqlCommand(query, cn))
                {
                    // open connection, execute command and close connection
                    cmd.Parameters.Add("@id", MySql.Data.MySqlClient.MySqlDbType.UInt32).Value = package_ID;
                    cn.Open();
                    MySqlDataReader reader = cmd.ExecuteReader();


                    while (reader.Read())
                    {
                        Package package = new Package();
                        package.Package_ID = int.Parse(reader["Package_ID"].ToString());
                        package.Package_Name = reader["Package_Name"].ToString();
                        package.Package_Code = reader["Package_Code"].ToString();
                        package.Package_Password = reader["Package_Password"].ToString();
                        package.Package_URL = reader["Package_URL"].ToString();
                        package.Price = reader["Price"].ToString();
                        package.Shared = Convert.ToBoolean(reader["Shared"].ToString());
                        package.Email_Result_ToUser = Convert.ToBoolean(reader["Email_Result_ToUser"].ToString());
                        package.AssociatedTests = reader["AssociatedTests"].ToString();
                        package.ImagePath = reader["ImagePath"].ToString();
                        package.Package_ClassGroup = reader["Package_ClassGroup"].ToString();
                        lstPackage.Add(package);
                    }

                    cn.Close();
                }
            }
            return lstPackage;
        }

        public DataTable GetPackageDetailsOld()
        {
            //string ConnectionString = @"Data source=DESKTOP-28M703K\SQLEXPRESS; Database=Adhyapann; Integrated Security=SSPI;";

            // Collecting Values
            DataTable dtPackage = new DataTable();

            // Query to be executed
            string query = "Select Package_ID, Package_Name, Package_URL,Package_Code,Package_Password, Shared, Price ,	Email_Result_ToUser, AssociatedTests,Completed ,Attended from package ";

            // instance connection and command
            using (MySqlConnection cn = GetConnection())


            using (MySqlCommand cmd = new MySqlCommand(query, cn))
            {
                // open connection, execute command and close connection
                cn.Open();
                using (MySqlDataAdapter da = new MySqlDataAdapter(cmd))
                {
                    // this will query your database and return the result to your datatable
                    da.Fill(dtPackage);
                    da.Dispose();
                }

                cn.Close();
            }
            return dtPackage;
        }

        public List<Test> GetTestDetails()
        {
            //string ConnectionString = @"Data source=DESKTOP-28M703K\SQLEXPRESS; Database=Adhyapann; Integrated Security=SSPI;";

            // Collecting Values
            List<Test> lstTest = new List<Test>();

            // Query to be executed
            string query = "Select Test_ID, Test_Name, TestTimer from test ";

            // instance connection and command
            using (MySqlConnection cn = GetConnection())
            {
                using (MySqlCommand cmd = new MySqlCommand(query, cn))
                {
                    // open connection, execute command and close connection
                    cn.Open();
                    MySqlDataReader reader = cmd.ExecuteReader();


                    while (reader.Read())
                    {
                        Test test = new Test();
                        test.Test_ID = int.Parse(reader["Test_ID"].ToString());
                        test.Test_Name = reader["Test_Name"].ToString();
                        test.TestTimer = int.Parse(reader["TestTimer"].ToString());

                        lstTest.Add(test);
                    }

                    cn.Close();
                }
            }
            return lstTest;
        }


        public DataTable SearchPackage(int Package_ID, string Package_Name, string Package_URL, string Package_Code, string Package_Password, bool Shared, string Price, bool Email_Result_ToUser, string AssociatedTests)
        {
            //string ConnectionString = @"Data source=DESKTOP-28M703K\SQLEXPRESS; Database=Adhyapann; Integrated Security=SSPI;";

            // Collecting Values
            DataTable dtPackage = new DataTable();

            // Query to be executed
            string query = "Select Package_ID, Package_Name, Package_URL,Package_Code,Package_Password, Shared, Price ,	Email_Result_ToUser, AssociatedTests,Completed ,Attended from package ";

            // instance connection and command
            using (MySqlConnection cn = GetConnection())
            using (MySqlCommand cmd = new MySqlCommand(query, cn))
            {
                // open connection, execute command and close connection
                cn.Open();
                using (MySqlDataAdapter da = new MySqlDataAdapter(cmd))
                {
                    // this will query your database and return the result to your datatable
                    da.Fill(dtPackage);
                    da.Dispose();
                }

                cn.Close();
            }
            return dtPackage;
        }

        public List<Question> GetSetQuestions(int subtest_ID)
        {
            //string ConnectionString = @"Data source=DESKTOP-28M703K\SQLEXPRESS; Database=Adhyapann; Integrated Security=SSPI;";

            // Collecting Values
            List<Question> lstQuestion = new List<Question>();

            // Query to be executed
            string query = "SELECT questions.QuestionID, questions.SubTest_ID, questions.IsPracticeQuestion, questions.Question, questions.Option1, questions.Option2, questions.Option3, questions.Option4, questions.Option5, questions.CorrectAnswer, subtest.SubTestTimer, subtest.SubTest_Name FROM questions INNER JOIN subtest ON Questions.SubTest_ID = subtest.SubTest_ID where subtest.SubTest_ID = @id AND Questions.IsPracticeQuestion = 0";

            // instance connection and command
            using (MySqlConnection cn = GetConnection())
            {
                using (MySqlCommand cmd = new MySqlCommand(query, cn))
                {
                    // open connection, execute command and close connection
                    cmd.Parameters.Add("@id", MySql.Data.MySqlClient.MySqlDbType.UInt32).Value = subtest_ID;
                    cn.Open();
                    MySqlDataReader reader = cmd.ExecuteReader();

                    while (reader.Read())
                    {
                        Question question = new Question();
                        question.Question_ID = int.Parse(reader["QuestionID"].ToString());
                        question.SubTest_ID = int.Parse(reader["SubTest_ID"].ToString());
                        question.Is_Practice_Question = Convert.ToBoolean(reader["IsPracticeQuestion"].ToString());
                        question.Question_Query = reader["Question"].ToString();
                        question.Option1 = reader["Option1"].ToString();
                        question.Option2 = reader["Option2"].ToString();
                        question.Option3 = reader["Option3"].ToString();
                        question.Option4 = reader["Option4"].ToString();
                        question.Option5 = reader["Option5"].ToString();
                        question.Correct_Answer = reader["CorrectAnswer"].ToString();
                        question.Sub_Test_Timer = int.Parse(reader["SubTestTimer"].ToString());
                        question.SubTest_Name = reader["SubTest_Name"].ToString();

                        lstQuestion.Add(question);
                    }
                    cn.Close();
                }
            }
            return lstQuestion;
        }

        public List<Question> GetPracticeQuestions(int subtest_ID)
        {
            //string ConnectionString = @"Data source=DESKTOP-28M703K\SQLEXPRESS; Database=Adhyapann; Integrated Security=SSPI;";

            // Collecting Values
            List<Question> lstQuestion = new List<Question>();

            // Query to be executed
            string query = "SELECT questions.QuestionID, questions.SubTest_ID, questions.IsPracticeQuestion, questions.Question, questions.Option1, questions.Option2, questions.Option3, questions.Option4, questions.Option5, questions.CorrectAnswer, subtest.SubTestTimer, subtest.SubTest_Name FROM questions INNER JOIN subtest ON questions.SubTest_ID = subtest.SubTest_ID where subTest.SubTest_ID = @id AND questions.IsPracticeQuestion = 1";

            // instance connection and command
            using (MySqlConnection cn = GetConnection())
            {
                using (MySqlCommand cmd = new MySqlCommand(query, cn))
                {
                    // open connection, execute command and close connection
                    cmd.Parameters.Add("@id", MySql.Data.MySqlClient.MySqlDbType.UInt32).Value = subtest_ID;
                    cn.Open();
                    MySqlDataReader reader = cmd.ExecuteReader();

                    while (reader.Read())
                    {
                        Question question = new Question();
                        question.Question_ID = int.Parse(reader["QuestionID"].ToString());
                        question.SubTest_ID = int.Parse(reader["SubTest_ID"].ToString());
                        question.Is_Practice_Question = Convert.ToBoolean(reader["IsPracticeQuestion"].ToString());
                        question.Question_Query = reader["Question"].ToString();
                        question.Option1 = reader["Option1"].ToString();
                        question.Option2 = reader["Option2"].ToString();
                        question.Option3 = reader["Option3"].ToString();
                        question.Option4 = reader["Option4"].ToString();
                        question.Option5 = reader["Option5"].ToString();
                        question.Correct_Answer = reader["CorrectAnswer"].ToString();
                        question.Sub_Test_Timer = int.Parse(reader["SubTestTimer"].ToString());
                        question.SubTest_Name = reader["SubTest_Name"].ToString();

                        lstQuestion.Add(question);
                    }
                    cn.Close();
                }
            }
            return lstQuestion;
        }

        public List<TestAnswerMapping> GetTestAnswersDetails(string category)
        {
            //string ConnectionString = @"Data source=DESKTOP-28M703K\SQLEXPRESS; Database=Adhyapann; Integrated Security=SSPI;";

            // Collecting Values           
            List<TestAnswerMapping> lstTestAnswers = new List<TestAnswerMapping>();
            // Query to be executed
            string query = "Select ID,Category,Question  ,Answer from test_answermapping where Category = @Category";

            // instance connection and command
            using (MySqlConnection cn = GetConnection())
            {
                using (MySqlCommand cmd = new MySqlCommand(query, cn))
                {
                    // open connection, execute command and close connection
                    cmd.Parameters.Add("@Category", MySql.Data.MySqlClient.MySqlDbType.VarChar, 100).Value = category;
                    cn.Open();
                    MySqlDataReader reader = cmd.ExecuteReader();


                    while (reader.Read())
                    {
                        TestAnswerMapping testAnswer = new TestAnswerMapping();
                        testAnswer.Category = reader["Category"].ToString();
                        testAnswer.Answer = reader["Answer"].ToString();
                        testAnswer.Question = reader["Question"].ToString();

                        lstTestAnswers.Add(testAnswer);
                    }

                    cn.Close();
                }
            }
            return lstTestAnswers;
        }

        public void UpdateTestScore(int score, string testName, string reference_code)
        {
            //string ConnectionString = @"Data source=DESKTOP-28M703K\SQLEXPRESS; Database=Adhyapann; Integrated Security=SSPI;";

            // Collecting Values


            // Query to be executed
            string query = "Update student_testinfo Set " + testName + " = " + "@score where  reference_code =@reference_code";


            // instance connection and command
            using (MySqlConnection cn = GetConnection())
            using (MySqlCommand cmd = new MySqlCommand(query, cn))
            {
                // add parameters and their values
                cmd.Parameters.Add("@score", MySql.Data.MySqlClient.MySqlDbType.UInt32, 255).Value = score;
                cmd.Parameters.Add("@reference_code", MySql.Data.MySqlClient.MySqlDbType.VarChar, 255).Value = reference_code;

                // open connection, execute command and close connection
                cn.Open();
                cmd.ExecuteNonQuery();
                cn.Close();
            }
        }

        public void UpdateTestScoreERSenior(string reference_code, int ER_Self_Blame, int ER_Acceptance, int ER_Rumination, int ER_PositiveRefocusing, int ER_RefocusonPlanning, int ER_PositiveReappraisal, int ER_PuttingintoPerspective, int ER_Catastrophizing, int ER_Other_blame)
        {
            //string ConnectionString = @"Data source=DESKTOP-28M703K\SQLEXPRESS; Database=Adhyapann; Integrated Security=SSPI;";

            // Collecting Values


            // Query to be executed
            string query = "Update student_testinfo Set ER_Self_Blame=@ER_Self_Blame, ER_Acceptance=@ER_Acceptance, ER_Rumination=@ER_Rumination, ER_PositiveRefocusing=@ER_PositiveRefocusing,ER_RefocusonPlanning=@ER_RefocusonPlanning, ER_PositiveReappraisal=@ER_PositiveReappraisal, ER_PuttingintoPerspective=@ER_PuttingintoPerspective,ER_Catastrophizing=@ER_Catastrophizing, ER_Other_blame=@ER_Other_blame,CompletionDate =@Date_Completed, Completed= @Completed  where  reference_code =@reference_code";


            // instance connection and command
            using (MySqlConnection cn = GetConnection())
            using (MySqlCommand cmd = new MySqlCommand(query, cn))
            {
                // add parameters and their values
                cmd.Parameters.Add("@ER_Self_Blame", MySql.Data.MySqlClient.MySqlDbType.UInt32).Value = ER_Self_Blame;
                cmd.Parameters.Add("@ER_Acceptance", MySql.Data.MySqlClient.MySqlDbType.UInt32).Value = ER_Acceptance;
                cmd.Parameters.Add("@ER_Rumination", MySql.Data.MySqlClient.MySqlDbType.UInt32).Value = ER_Rumination;
                cmd.Parameters.Add("@ER_PositiveRefocusing", MySql.Data.MySqlClient.MySqlDbType.UInt32).Value = ER_PositiveRefocusing;
                cmd.Parameters.Add("@ER_RefocusonPlanning", MySql.Data.MySqlClient.MySqlDbType.UInt32).Value = ER_RefocusonPlanning;
                cmd.Parameters.Add("@ER_PositiveReappraisal", MySql.Data.MySqlClient.MySqlDbType.UInt32).Value = ER_PositiveReappraisal;
                cmd.Parameters.Add("@ER_PuttingintoPerspective", MySql.Data.MySqlClient.MySqlDbType.UInt32).Value = ER_PuttingintoPerspective;
                cmd.Parameters.Add("@ER_Catastrophizing", MySql.Data.MySqlClient.MySqlDbType.UInt32).Value = ER_Catastrophizing;
                cmd.Parameters.Add("@ER_Other_blame", MySql.Data.MySqlClient.MySqlDbType.UInt32).Value = ER_Other_blame;

                cmd.Parameters.Add("@reference_code", MySql.Data.MySqlClient.MySqlDbType.VarChar, 255).Value = reference_code;
                cmd.Parameters.Add("@Date_Completed", MySql.Data.MySqlClient.MySqlDbType.DateTime).Value = DateTime.Now;
                cmd.Parameters.Add("@Completed", MySql.Data.MySqlClient.MySqlDbType.Bit).Value =true;

                // open connection, execute command and close connection
                cn.Open();
                cmd.ExecuteNonQuery();
                cn.Close();
            }
        }

        public List<ScaledScoreMapping> GetScaledScoreMapping(int Age)
        {
            //string ConnectionString = @"Data source=DESKTOP-28M703K\SQLEXPRESS; Database=Adhyapann; Integrated Security=SSPI;";

            // Collecting Values
            List<ScaledScoreMapping> scaledScoreMaster = new List<ScaledScoreMapping>();
            string table_name = String.Empty;

            // Query to be executed
            if (Age >= 13 && Age <= 17)
            {
                table_name = "aptitude_scaled_scores13_17";
            }
            else if (Age >= 18 && Age <= 19)
            {
                table_name = "aptitude_scaled_scores18_19";
            }


            string query = "SELECT  ID ,Verbal_INF ,Verbal_COM,Verbal_ARI,Verbal_SIM,Verbal_VOC,Verbal_Scaled_Score,Performance_DS,Performance_PC,Performance_SPA ,Performance_PA,Performance_OA,Performance_Scaled_Score  from " + table_name;
            //string verbal_inf_query = "SELECT TOP 1 Verbal_Scaled_Score FROM " + table_name.ToString() + " where Verbal_INF <= @score Order by Verbal_INF DESC";
            //string verbal_com_query = "SELECT TOP 1 Verbal_Scaled_Score FROM " + table_name.ToString() + " where Verbal_COM <= @score Order by Verbal_COM DESC";
            //string verbal_ari_query = "SELECT TOP 1 Verbal_Scaled_Score FROM " + table_name.ToString() + " where Verbal_ARI <= @score Order by Verbal_ARI DESC";
            //string verbal_sim_query = "SELECT TOP 1 Verbal_Scaled_Score FROM " + table_name.ToString() + " where Verbal_SIM <= @score Order by Verbal_SIM DESC";
            //string verbal_voc_query = "SELECT TOP 1 Verbal_Scaled_Score FROM " + table_name.ToString() + " where Verbal_VOC <= @score Order by Verbal_VOC DESC";
            //string per_ds_query = "SELECT TOP 1 Performance_Scaled_Score FROM " + table_name.ToString() + " where Performance_DS <= @score Order by Performance_DS DESC";
            //string per_pc_query = "SELECT TOP 1 Performance_Scaled_Score FROM " + table_name.ToString() + " where Performance_PC <= @score Order by Performance_PC DESC";
            //string per_spa_query = "SELECT TOP 1 Performance_Scaled_Score FROM " + table_name.ToString() + " where Performance_SPA <= @score Order by Performance_SPA DESC";
            //string per_pa_query = "SELECT TOP 1 Performance_Scaled_Score FROM " + table_name.ToString() + " where Performance_PA <= @score Order by Performance_PA DESC";
            //string per_oa_query = "SELECT TOP 1 Performance_Scaled_Score FROM " + table_name.ToString() + " where Performance_OA <= @score Order by Performance_OA DESC";

            // instance connection and command
            using (MySqlConnection cn = GetConnection())
            {
                using (MySqlCommand cmd = new MySqlCommand(query, cn))
                {
                    // open connection, execute command and close connection
                    cn.Open();
                    MySqlDataReader reader = cmd.ExecuteReader();


                    while (reader.Read())
                    {
                        ScaledScoreMapping scaledScore = new ScaledScoreMapping();
                        scaledScore.Verbal_INF = int.Parse(reader["Verbal_INF"].ToString());
                        scaledScore.Verbal_COM = int.Parse(reader["Verbal_COM"].ToString());
                        scaledScore.Verbal_ARI = int.Parse(reader["Verbal_ARI"].ToString());
                        scaledScore.Verbal_SIM = int.Parse(reader["Verbal_SIM"].ToString());
                        scaledScore.Verbal_VOC = int.Parse(reader["Verbal_VOC"].ToString());
                        scaledScore.Verbal_Scaled_Score = int.Parse(reader["Verbal_Scaled_Score"].ToString());
                        scaledScore.Performance_DS = int.Parse(reader["Performance_DS"].ToString());
                        scaledScore.Performance_PC = int.Parse(reader["Performance_PC"].ToString());
                        scaledScore.Performance_PA = int.Parse(reader["Performance_PA"].ToString());
                        scaledScore.Performance_SPA = int.Parse(reader["Performance_SPA"].ToString());
                        scaledScore.Performance_OA = int.Parse(reader["Performance_OA"].ToString());
                        scaledScore.Performance_Scaled_Score = int.Parse(reader["Performance_Scaled_Score"].ToString());

                        scaledScoreMaster.Add(scaledScore);
                    }

                    cn.Close();
                }

            }
            return scaledScoreMaster;
        }
       
        public List<IQandPercentileMapping> GetIQandPercentileMapping(int Age)
        {
            //string ConnectionString = @"Data source=DESKTOP-28M703K\SQLEXPRESS; Database=Adhyapann; Integrated Security=SSPI;";

            // Collecting Values
            List<IQandPercentileMapping> IQandPercentileMapping = new List<IQandPercentileMapping>();
            string table_name = String.Empty;

            // Table Name for query
            if (Age >= 13 && Age <= 17)
            {
                table_name = "aptitudeiqandpercentile13_17";
            }
            else if (Age >= 18 && Age <= 19)
            {
                table_name = "aptitudeiqandpercentile18_19";
            }
            string query = "SELECT Total_Scaled_Verbal_Score,Scaled_Verbal_Score_IQ ,Scaled_Verbal_Score_Percentile ,Total_Scaled_Performance_Score,Scaled_Performance_Score_IQ ,Scaled_Performance_Score_Percentile ,Full_Score ,Full_Score_IQ,Full_Score_Percentile  from " + table_name;
            //string verbal_scaled_query = "SELECT TOP 1 Scaled_Verbal_Score_IQ, Scaled_Verbal_Score_Percentile FROM " + table_name + " where Total_Scaled_Verbal_Score <= @score Order by Total_Scaled_Verbal_Score DESC";
            //string performance_scaled_query = "SELECT TOP 1 Scaled_Performance_Score_IQ, Scaled_Performance_Score_Percentile FROM " + table_name + " where Total_Scaled_Performance_Score <= @score Order by Total_Scaled_Performance_Score DESC";
            //string total_scaled_query = "SELECT TOP 1 Full_Score_IQ, Full_Score_Percentile FROM " + table_name + " where Full_Score <= @score Order by Full_Score DESC";


            // instance connection and command
            using (MySqlConnection cn = GetConnection())
            {
                
                using (MySqlCommand cmd = new MySqlCommand(query, cn))
                {
                    // open connection, execute command and close connection
                    cn.Open();
                    MySqlDataReader reader = cmd.ExecuteReader();
                    while (reader.Read())
                    {
                        IQandPercentileMapping qandPercentile = new IQandPercentileMapping();
                        qandPercentile.Full_Score = int.Parse(reader["Full_Score"].ToString());
                        qandPercentile.Full_Score_IQ = int.Parse(reader["Full_Score_IQ"].ToString());
                        qandPercentile.Full_Score_Percentile = int.Parse(reader["Full_Score_Percentile"].ToString());
                        qandPercentile.Scaled_Performance_Score_IQ = int.Parse(reader["Scaled_Performance_Score_IQ"].ToString());
                        qandPercentile.Scaled_Performance_Score_Percentile = int.Parse(reader["Scaled_Performance_Score_Percentile"].ToString());
                        qandPercentile.Scaled_Verbal_Score_IQ = int.Parse(reader["Scaled_Verbal_Score_IQ"].ToString());
                        qandPercentile.Scaled_Verbal_Score_Percentile = int.Parse(reader["Scaled_Verbal_Score_Percentile"].ToString());
                        qandPercentile.Total_Scaled_Performance_Score = int.Parse(reader["Total_Scaled_Performance_Score"].ToString());
                        qandPercentile.Total_Scaled_Verbal_Score = int.Parse(reader["Total_Scaled_Verbal_Score"].ToString());

                        IQandPercentileMapping.Add(qandPercentile);
                    }

                    cn.Close();
                }
                
            }
            return IQandPercentileMapping;
        }

        public StudentTestInfo GetScores(string ref_code)
        {
            //string ConnectionString = @"Data source=DESKTOP-28M703K\SQLEXPRESS; Database=Adhyapann; Integrated Security=SSPI;";

            // Collecting Values
            StudentTestInfo score = new StudentTestInfo();

            // Query to be executed
            string query = "SELECT * from student_testinfo where Reference_Code = @reference_code";

            // instance connection and command
            using (MySqlConnection cn = GetConnection())
            {
                using (MySqlCommand cmd = new MySqlCommand(query, cn))
                {
                    // open connection, execute command and close connection
                    cmd.Parameters.AddWithValue("@reference_code", ref_code.ToString());
                    cn.Open();
                    MySqlDataReader reader = cmd.ExecuteReader();

                    while (reader.Read())
                    {
                        score.Student_TestID = reader["Student_TestID"].ToString();
                        score.Name = reader["Name"].ToString();
                        score.School_Name = reader["School_Name"].ToString();
                        score.Gender = reader["Gender"].ToString();
                        score.Email_ID = reader["Email_ID"].ToString();
                        score.Class = reader["Class"].ToString();
                        score.DOB = reader["DOB"].ToString();
                        score.Age = int.Parse(reader["Age"].ToString());
                        score.Reference_Code = reader["Reference_Code"].ToString();
                        score.Package_ID = int.Parse(reader["Package_ID"].ToString());
                        score.Package_Name = reader["Package_Name"].ToString();
                        score.Verbal_INF = int.Parse(reader["Verbal_INF"].ToString());
                        score.Verbal_COM = int.Parse(reader["Verbal_COM"].ToString());
                        score.Verbal_ARI = int.Parse(reader["Verbal_ARI"].ToString());
                        score.Verbal_SIM = int.Parse(reader["Verbal_SIM"].ToString());
                        score.Verbal_VOC = int.Parse(reader["Verbal_VOC"].ToString());
                        score.Performance_DS = int.Parse(reader["Performance_DS"].ToString());
                        score.Performance_PC = int.Parse(reader["Performance_PC"].ToString());
                        score.Performance_SPA = int.Parse(reader["Performance_SPA"].ToString());
                        score.Performance_PA = int.Parse(reader["Performance_PA"].ToString());
                        score.Performance_OA = int.Parse(reader["Performance_OA"].ToString());
                        if (!String.IsNullOrEmpty(reader["ER_Self_Blame"].ToString()))
                            score.ER_Self_Blame = int.Parse(reader["ER_Self_Blame"].ToString());
                        if (!String.IsNullOrEmpty(reader["ER_Acceptance"].ToString()))
                            score.ER_Acceptance = int.Parse(reader["ER_Acceptance"].ToString());
                        if (!String.IsNullOrEmpty(reader["ER_Rumination"].ToString()))
                            score.ER_Rumination = int.Parse(reader["ER_Rumination"].ToString());
                        if (!String.IsNullOrEmpty(reader["ER_PositiveRefocusing"].ToString()))
                            score.ER_PositiveRefocusing = int.Parse(reader["ER_PositiveRefocusing"].ToString());
                        if (!String.IsNullOrEmpty(reader["ER_RefocusonPlanning"].ToString()))
                            score.ER_RefocusonPlanning = int.Parse(reader["ER_RefocusonPlanning"].ToString());
                        if (!String.IsNullOrEmpty(reader["ER_PositiveReappraisal"].ToString()))
                            score.ER_PositiveReappraisal = int.Parse(reader["ER_PositiveReappraisal"].ToString());
                        if (!String.IsNullOrEmpty(reader["ER_PuttingintoPerspective"].ToString()))
                            score.ER_PuttingintoPerspective = int.Parse(reader["ER_PuttingintoPerspective"].ToString());
                        if (!String.IsNullOrEmpty(reader["ER_Catastrophizing"].ToString()))
                            score.ER_Catastrophizing = int.Parse(reader["ER_Catastrophizing"].ToString());
                        if (!String.IsNullOrEmpty(reader["ER_Other_blame"].ToString()))
                            score.ER_Other_blame = int.Parse(reader["ER_Other_blame"].ToString());
                        if (!String.IsNullOrEmpty(reader["Verbal_Scaled_INF"].ToString()))
                            score.Verbal_Scaled_INF = int.Parse(reader["Verbal_Scaled_INF"].ToString());
                        if (!String.IsNullOrEmpty(reader["Verbal_Scaled_COM"].ToString()))
                            score.Verbal_Scaled_COM = int.Parse(reader["Verbal_Scaled_COM"].ToString());
                        if (!String.IsNullOrEmpty(reader["Verbal_Scaled_ARI"].ToString()))
                            score.Verbal_Scaled_ARI = int.Parse(reader["Verbal_Scaled_ARI"].ToString());
                        if (!String.IsNullOrEmpty(reader["Verbal_Scaled_SIM"].ToString()))
                            score.Verbal_Scaled_SIM = int.Parse(reader["Verbal_Scaled_SIM"].ToString());
                        if (!String.IsNullOrEmpty(reader["Verbal_Scaled_VOC"].ToString()))
                            score.Verbal_Scaled_VOC = int.Parse(reader["Verbal_Scaled_VOC"].ToString());
                        if (!String.IsNullOrEmpty(reader["Performance_Scaled_DS"].ToString()))
                            score.Performance_Scaled_DS = int.Parse(reader["Performance_Scaled_DS"].ToString());
                        if (!String.IsNullOrEmpty(reader["Performance_Scaled_PC"].ToString()))
                            score.Performance_Scaled_PC = int.Parse(reader["Performance_Scaled_PC"].ToString());
                        if (!String.IsNullOrEmpty(reader["Performance_Scaled_SPA"].ToString()))
                            score.Performance_Scaled_SPA = int.Parse(reader["Performance_Scaled_SPA"].ToString());
                        if (!String.IsNullOrEmpty(reader["Performance_Scaled_PA"].ToString()))
                            score.Performance_Scaled_PA = int.Parse(reader["Performance_Scaled_PA"].ToString());
                        if (!String.IsNullOrEmpty(reader["Performance_Scaled_OA"].ToString()))
                            score.Performance_Scaled_OA = int.Parse(reader["Performance_Scaled_OA"].ToString());
                        if (!String.IsNullOrEmpty(reader["Total_Verbal_Score"].ToString()))
                            score.Total_Verbal_Score = int.Parse(reader["Total_Verbal_Score"].ToString());
                        if (!String.IsNullOrEmpty(reader["IQ_Verbal"].ToString()))
                            score.IQ_Verbal = int.Parse(reader["IQ_Verbal"].ToString());
                        if (!String.IsNullOrEmpty(reader["Percentile_Verbal"].ToString()))
                            score.Percentile_Verbal = int.Parse(reader["Percentile_Verbal"].ToString());
                        if (!String.IsNullOrEmpty(reader["Total_Performance_Score"].ToString()))
                            score.Total_Performance_Score = int.Parse(reader["Total_Performance_Score"].ToString());
                        if (!String.IsNullOrEmpty(reader["IQ_Perfromance"].ToString()))
                            score.IQ_Perfromance = int.Parse(reader["IQ_Perfromance"].ToString());
                        if (!String.IsNullOrEmpty(reader["Percentile_Performance"].ToString()))
                            score.Percentile_Performance = int.Parse(reader["Percentile_Performance"].ToString());
                        if (!String.IsNullOrEmpty(reader["Full_Scale_Score"].ToString()))
                            score.Full_Scale_Score = int.Parse(reader["Full_Scale_Score"].ToString());
                        if (!String.IsNullOrEmpty(reader["Full_Scale_IQ"].ToString()))
                            score.Full_Scale_IQ = int.Parse(reader["Full_Scale_IQ"].ToString());
                        if (!String.IsNullOrEmpty(reader["Full_Percentile"].ToString()))
                            score.Full_Percentile = int.Parse(reader["Full_Percentile"].ToString());

                        score.TestDate = String.Format("{0:d/M/yyyy HH:mm:ss}", reader["TestDate"]);


                    }
                    cn.Close();
                }
            }
            return score;
        }

        public string SetScores(string ref_code, int Verbal_INF, int Verbal_COM, int Verbal_ARI, int Verbal_SIM, int Verbal_VOC, int Performance_DS, int Performance_PC, int Performance_SPA, int Performance_PA, int Performance_OA, int verbal_total_score, int performance_total_score, int total_score, int verbal_IQ, int verbal_percentile, int performabce_IQ, int performance_percentile, int total_IQ, int total_percentile)
        {
            string status = String.Empty;
            try
            {
                //string ConnectionString = @"Data source=DESKTOP-28M703K\SQLEXPRESS; Database=Adhyapann; Integrated Security=SSPI;";

                // Collecting Values
                List<StudentTestInfo> studentScore = new List<StudentTestInfo>();

                // Query to be executed
                    string query = "Update student_testinfo Set Verbal_Scaled_INF = @Verbal_INF, Verbal_Scaled_COM = @Verbal_COM, Verbal_Scaled_ARI = @Verbal_ARI, Verbal_Scaled_SIM = @Verbal_SIM, Verbal_Scaled_VOC = @Verbal_VOC, Performance_Scaled_DS = @Performance_DS, Performance_Scaled_PC = @Performance_PC, Performance_Scaled_SPA = @Performance_SPA, Performance_Scaled_PA = @Performance_PA, Performance_Scaled_OA = @Performance_OA, Total_Verbal_Score = @verbal_total_score, IQ_Verbal = @verbal_IQ, Percentile_Verbal = @verbal_percentile, Total_Performance_Score = @performance_total_score, IQ_Perfromance = @performabce_IQ, Percentile_Performance = @performance_percentile, Full_Scale_Score = @total_score, Full_Scale_IQ = @total_IQ, Full_Percentile = @total_percentile where Reference_Code = @ref_code";

                // instance connection and command
                using (MySqlConnection cn = GetConnection())
                {
                    using (MySqlCommand cmd = new MySqlCommand(query, cn))
                    {
                        // open connection, execute command and close connection
                        cmd.Parameters.Add("@Verbal_INF", MySql.Data.MySqlClient.MySqlDbType.UInt32).Value = Verbal_INF;
                        cmd.Parameters.Add("@Verbal_COM", MySql.Data.MySqlClient.MySqlDbType.UInt32).Value = Verbal_COM;
                        cmd.Parameters.Add("@Verbal_ARI", MySql.Data.MySqlClient.MySqlDbType.UInt32).Value = Verbal_ARI;
                        cmd.Parameters.Add("@Verbal_SIM", MySql.Data.MySqlClient.MySqlDbType.UInt32).Value = Verbal_SIM;
                        cmd.Parameters.Add("@Verbal_VOC", MySql.Data.MySqlClient.MySqlDbType.UInt32).Value = Verbal_VOC;
                        cmd.Parameters.Add("@Performance_DS", MySql.Data.MySqlClient.MySqlDbType.UInt32).Value = Performance_DS;
                        cmd.Parameters.Add("@Performance_PC", MySql.Data.MySqlClient.MySqlDbType.UInt32).Value = Performance_PC;
                        cmd.Parameters.Add("@Performance_SPA", MySql.Data.MySqlClient.MySqlDbType.UInt32).Value = Performance_SPA;
                        cmd.Parameters.Add("@Performance_PA", MySql.Data.MySqlClient.MySqlDbType.UInt32).Value = Performance_PA;
                        cmd.Parameters.Add("@Performance_OA", MySql.Data.MySqlClient.MySqlDbType.UInt32).Value = Performance_OA;
                        cmd.Parameters.Add("@verbal_total_score", MySql.Data.MySqlClient.MySqlDbType.UInt32).Value = verbal_total_score;
                        cmd.Parameters.Add("@verbal_IQ", MySql.Data.MySqlClient.MySqlDbType.UInt32).Value = verbal_IQ;
                        cmd.Parameters.Add("@verbal_percentile", MySql.Data.MySqlClient.MySqlDbType.UInt32).Value = verbal_percentile;
                        cmd.Parameters.Add("@performance_total_score", MySql.Data.MySqlClient.MySqlDbType.UInt32).Value = performance_total_score;
                        cmd.Parameters.Add("@performabce_IQ", MySql.Data.MySqlClient.MySqlDbType.UInt32).Value = performabce_IQ;
                        cmd.Parameters.Add("@performance_percentile", MySql.Data.MySqlClient.MySqlDbType.UInt32).Value = performance_percentile;
                        cmd.Parameters.Add("@total_score", MySql.Data.MySqlClient.MySqlDbType.UInt32).Value = total_score;
                        cmd.Parameters.Add("@total_IQ", MySql.Data.MySqlClient.MySqlDbType.UInt32).Value = total_IQ;
                        cmd.Parameters.Add("@total_percentile", MySql.Data.MySqlClient.MySqlDbType.UInt32).Value = total_percentile;

                        cmd.Parameters.AddWithValue("@ref_code", ref_code.ToString());
                        cn.Open();
                        cmd.ExecuteNonQuery();
                        status = "success";
                        cn.Close();
                    }
                }
                return status;
            }
            catch (Exception ex)
            {
                status = ex.Message.ToString();
                return status;
            }

        }
    }
}
