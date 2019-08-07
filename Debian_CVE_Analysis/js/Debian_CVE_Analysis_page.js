// Copyright 2018 BlueCat Networks. All rights reserved.
// JavaScript for your page goes in here.

$(document).ready(function()
{

    $('#ip_address').prop("disabled",false);
    $('#ssh_user').prop("disabled",false);
    $('#password').prop("disabled",false);
    $('#cve').prop("disabled",false);
    //$('#submit').prop("disabled",false);
    $('#action').prop("disabled",false);
    $('#cve_2').prop("disabled",false);
    //$('#rel').prop("disabled",true);
    $('#submit2').prop("disabled",false);

    $("label[for='emptyField']").html(" <p><h2>Please Enter new CVE and REL values</h2></p>")
    $("<div id='output1'> </div>").insertAfter("input[id='submit']")
var ConnectForm = $('#submit');
var AddCVE = $('#submit2');




    $('#ip_address').change(function(){
        if($('#ip_address').val() == ""){
            $('#submit').prop("disabled", true);
        }
        else {
            $('#submit').prop("disabled", false);
        }
    })

    $('#action').change(function() {
        $('#rel').attr("disabled", $('#action').val() == "Search").val("");
        $('#password2').attr("disabled", $('#action').val() == "Search").val("");
        });
//Log Display Javascript
ConnectForm.bind('click',function(event){
    event.preventDefault();
    var ip_address1 = $('#ip_address').val();
    var ssh_user1 = $('#ssh_user').val();
    var password1 = $('#password').val();
    var cve1 = $('#cve').val();
    //alert(ip_address1);
   $.ajax({
        type: "POST",
        url:"yield1", //the page containing python script

        dataType: "text",
        data: {ip_address:ip_address1,ssh_user:ssh_user1,password:password1,cve:cve1},
        success: function (data) {
        console.log(data)
        data = data.replace(/\"/g, "")
         $("#output1").html(data);
         $("#output2").html(" ");
}
});
});


AddCVE.bind('click',function(event){
    event.preventDefault();
    var rel = $('#rel').val();
    var cve = $('#cve_2').val();
    var password2 = $('#password2').val();
    var action = $('#action').val();

    //alert(ip_address1);
   $.ajax({
        type: "POST",
        url:"yield2", //the page containing python script

        dataType: "text",
        data: {rel:rel, cve : cve, action : action, password2 : password2},
        success: function (data) {
        data = data.replace(/\"/g, "")
         $("#output2").html(data);
         $("#output1").html(" ");
}
});


});
});