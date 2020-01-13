using System;
using System.Collections.Generic;
using System.Text;

namespace DataAccessLayer
{
    public class StudentTestInfo
    {
        public string Student_TestID { get; set; }
        public string Name { get; set; }
        public string School_Name { get; set; }
        public string Gender { get; set; }
        public string Email_ID { get; set; }
        public string Class { get; set; }
        public string DOB { get; set; }
        public int Age { get; set; }
        public string Reference_Code { get; set; }
        public int Package_ID { get; set; }
        public string Package_Name { get; set; }
        public int Verbal_INF { get; set; }
        public int Verbal_COM { get; set; }
        public int Verbal_ARI { get; set; }
        public int Verbal_SIM { get; set; }
        public int Verbal_VOC { get; set; }
        public int Performance_DS { get; set; }
        public int Performance_PC { get; set; }
        public int Performance_SPA { get; set; }
        public int Performance_PA { get; set; }
        public int Performance_OA { get; set; }
        public int ER_Self_Blame { get; set; }
        public int ER_Acceptance { get; set; }
        public int ER_Rumination { get; set; }
        public int ER_PositiveRefocusing { get; set; }
        public int ER_RefocusonPlanning { get; set; }
        public int ER_PositiveReappraisal { get; set; }
        public int ER_PuttingintoPerspective { get; set; }
        public int ER_Catastrophizing { get; set; }
        public int ER_Other_blame { get; set; }
        public int Verbal_Scaled_INF { get; set; }
        public int Verbal_Scaled_COM { get; set; }
        public int Verbal_Scaled_ARI { get; set; }
        public int Verbal_Scaled_SIM { get; set; }
        public int Verbal_Scaled_VOC { get; set; }
        public int Performance_Scaled_DS { get; set; }
        public int Performance_Scaled_PC { get; set; }
        public int Performance_Scaled_SPA { get; set; }
        public int Performance_Scaled_PA { get; set; }
        public int Performance_Scaled_OA { get; set; }
        public int Total_Verbal_Score { get; set; }
        public int IQ_Verbal { get; set; }
        public int Percentile_Verbal { get; set; }
        public int Total_Performance_Score { get; set; }
        public int IQ_Perfromance { get; set; }
        public int Percentile_Performance { get; set; }
        public int Full_Scale_Score { get; set; }
        public int Full_Scale_IQ { get; set; }
        public int Full_Percentile { get; set; }

        public bool Completed { get; set; }
        public string TestDate { get; set; }
        public string CompletionDate { get; set; }
    }
}
