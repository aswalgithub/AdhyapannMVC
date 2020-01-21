using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.ComponentModel.DataAnnotations;

namespace DataAccessLayer
{
    public class AdminDetail
    {
        public int ID { get; set; }
        public string User_Id { get; set; }
        public string Password { get; set; }
        public string Email_Id { get; set; }
        public string New_Email_Id { get; set; }

        public string New_Password { get; set; }

        public string Confirm_New_Password { get; set; }
    }
}
