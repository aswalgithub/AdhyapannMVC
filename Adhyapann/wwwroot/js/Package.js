$(document).ready(function ($) {
    $(function () {
        $('#btnSearchPackage').click(function (event) {

            var input = new Object();
            input.PackageName = $('#txtPackageName').val();
            input.PackageCode = $('#txtPackageCode').val();

            $.ajax({
                type: 'POST',
                url: '../Admin/SearchPackage',
                data: JSON.stringify(input),
                contentType: 'application/json; charset=utf-8',
                //data: JSON.stringify({ PackageName: 1, PackageCode: 1 }),
                dataType: 'json',
                async: true,
                processData: false,
                success: function (result) {

                    //var trHTML = '';
                    $("#tblPackage").children().remove();
                    //$("#tblPackage").datatable().fnDestroy();

                    trHTML = '<thead>< tr ><th scope="col">Package Name</th> <th scope="col">Package Code</th><th scope="col">Package Group</th> <th scope="col">Password</th><th scope="col">Shared</th><th scope="col">Price</th> <th scope="col">Email Result To User</th>  <th scope="col">Associated Tests</th> <th scope="col">Edit</th> <th scope="col">Delete</th>  </tr > </thead >'
                    $.each(result.lstPackages, function (i, item) {
                        
                        trHTML += '<tr><td>' + result.lstPackages[i].Package_Name + '</td><td>' + result.lstPackages[i].Package_Code + '</td><td>' + result.lstPackages[i].Package_ClassGroup + '</td><td>' + result.lstPackages[i].Package_Password + '</td><td>' + result.lstPackages[i].Shared + '</td><td>' + result.lstPackages[i].Price + '</td><td>' + result.lstPackages[i].Email_Result_ToUser + '</td><td>' + result.lstPackages[i].AssociatedTests + '</td><td>' + '<input style="color:red" type="button" value="Edit" name="EditPackage" Var1= ' + result.lstPackages[i].Package_ID + '></td ><td>' + '<input style="color:red" type="button" class="deletePackage" value="Delete" Var2= ' + result.lstPackages[i].Package_ID  + '></td >' + '</tr>';
                    });

                    $('#tblPackage').append(trHTML);

                    oTable6 = $('#tblPackage').dataTable({
                        "bDestroy": true,
                        "pageLength": 2
                    }
                    );
                },

                error: function (msg) {

                    alert(msg.responseText);
                }
            });
        });

       
        $('table').on('click', 'input[name="DeletePackage"]', function (e) {

            var id = $(this).attr("Var2");

            var MSG = confirm("Are you sure you want to delete this Record?");

            if (MSG) {

                $.ajax({
                    type: 'POST',
                    url: '../Admin/DeletePackage',
                    data: JSON.stringify(id),
                    contentType: 'application/json; charset=utf-8',
                    //data: JSON.stringify({ PackageName: 1, PackageCode: 1 }),
                    dataType: 'json',
                    async: true,
                    processData: false,
                    success: function (result) {
                        $("#tblPackage").children().remove();
                        //$("#tblPackage").datatable().fnDestroy();

                        trHTML = '<thead>< tr ><th scope="col">Package Name</th> <th scope="col">Package Code</th><th scope="col">Package Group</th> <th scope="col">Password</th><th scope="col">Shared</th><th scope="col">Price</th> <th scope="col">Email Result To User</th>  <th scope="col">Associated Tests</th> <th scope="col">Edit</th> <th scope="col">Delete</th>  </tr > </thead >'
                        $.each(result.lstPackages, function (i, item) {

                            trHTML += '<tr><td>' + result.lstPackages[i].Package_Name + '</td><td>' + result.lstPackages[i].Package_Code + '</td><td>' + result.lstPackages[i].Package_ClassGroup + '</td><td>' + result.lstPackages[i].Package_Password + '</td><td>' + result.lstPackages[i].Shared + '</td><td>' + result.lstPackages[i].Price + '</td><td>' + result.lstPackages[i].Email_Result_ToUser + '</td><td>' + result.lstPackages[i].AssociatedTests + '</td><td>' + '<input style="color:red" type="button" value="Edit" name="EditPackage" Var1= ' + result.lstPackages[i].Package_ID + '></td ><td>' + '<input style="color:red" type="button" class="deletePackage" value="Delete" Var2= ' + result.lstPackages[i].Package_ID + '></td >' + '</tr>';
                        });


                        $('#tblPackage').append(trHTML);

                        oTable6 = $('#tblPackage').dataTable({
                            "bDestroy": true,
                            "pageLength": 2

                        }
                        );
                    },
                    error: function () {
                        alert("Error while deleting data");
                    }
                });
            }
        })


        $('table').on('click', 'input[name="EditPackage"]', function (e) {

            var id = $(this).attr("Var1");

            window.location.href = '../Admin/SelectPackage' + "/" + id;
        })

        //$('#CreatePackage').click(function (event) {
        //    $("#frmCreatePackage").submit()
        //});
        

    });


});
