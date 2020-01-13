$(document).ready(function () {
    $("#password1").focusout(validate);
    $("#password1").blur(validate);

    function validate() {
        var password1 = $("#password1").val();
        var password2 = $("#password2").val();

        if (password1 == password2) {
            $("#validate-status").text("Valid Password");
            $("#validate-status").css('color', 'green');
        }
        else {
            $("#validate-status").text("Invalid Password");
            $("#validate-status").css('color', 'red');
        }

    }

   
});



