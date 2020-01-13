using System;
using System.Collections.Generic;
using System.Text;

namespace DataAccessLayer
{
    public class Package
    {
        public int Package_ID { get; set; }
        public string Package_Name { get; set; }
        public string Package_ClassGroup { get; set; }
        public string Package_URL { get; set; }
        public string Package_Code { get; set; }
        public string Package_Password { get; set; }
        public bool Shared { get; set; }
        public string Price { get; set; }
        public bool Email_Result_ToUser { get; set; }
        public string AssociatedTests { get; set; }
        public string[] Test_Name { get; set; }
        public int[] Test_ID { get; set; }

        public int Completed { get; set; }
        public int Attended { get; set; }

        public string ImagePath { get; set; }

    }
}
