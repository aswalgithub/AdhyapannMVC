using System;
using System.Collections.Generic;
using System.Text;

namespace DataAccessLayer
{
    public class BoolOptionEmailDecision
    {
        public string EmailDecision_ID { get; set; }
        public string EmailDecision_Name { get; set; }
    }
    public class BoolOptionShared
    {
        public string Shared_ID { get; set; }
        public string Shared_Name { get; set; }
    }

    public class PackageCategory
    {
        public string Package_ClassGroup_ID { get; set; }
        public string Package_ClassGroup { get; set; }
    }
}
