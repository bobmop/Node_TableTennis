$(document).ready(function () {
    $("#login").submit(function() {
        $.ajax({
            url: "/login",
            type: "POST",
            data: {
                username: $("#username").val(),
                password: $("#password").val()
            },
            success: function (data) {
                var token = data.token;
                $("#getusers").one("click", function() {
                    $.ajax({
                        url: "/user",
                        type: "GET",
                        beforeSend: function(xhr) {
                            xhr.setRequestHeader("token", data.token);
                        },
                        success: function(data) {
                            console.log(data);
                        },
                        error: function() {
                            console.log(arguments);
                        }
                    });
                });
                $("#adduser").show();
                $("#adduser").submit(function() {
                    var username = $("#add_username").val(),
                        password = $("#add_password").val(),
                        confirm  = $("#add_confirm").val();
                    if(!username || !password) {
                        alert("username/password required");
                    } else if(password !== confirm) {
                        alert("passwords mismatch");
                    } else {
                        $.ajax({
                            url: "/user",
                            type: "POST",
                            data: {
                                username: username,
                                password: password
                            },
                            beforeSend: function(xhr) {
                                xhr.setRequestHeader("token", data.token);
                            },
                            success: function(data) {
                                console.log(data);
                            },
                            error: function() {
                                console.log(arguments);
                            }
                        });
                    }

                    return false;
                });
            },
            error: function () {
                console.log(arguments);
            }
        });
        return false;
    });
});