<!DOCTYPE html>
<html>

<head>
    <title>Login Page</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f2f2f2;
            text-align: center;
        }
        
        h1 {
            color: #333;
        }
        
        #loginForm {
            background-color: #fff;
            border: 1px solid #ccc;
            max-width: 300px;
            margin: 0 auto;
            padding: 20px;
            border-radius: 5px;
        }
        
        label {
            display: block;
            text-align: left;
            margin-bottom: 5px;
        }
        
        input[type="text"],
        input[type="password"] {
            width: 90%;
            padding: 10px;
            margin-bottom: 10px;
            border: 1px solid #ccc;
            border-radius: 3px;
        }
        
        input[type="submit"] {
            background-color: #007bff;
            color: #fff;
            border: none;
            padding: 10px 20px;
            cursor: pointer;
            border-radius: 3px;
        }
        
        input[type="submit"]:hover {
            background-color: #0056b3;
        }
    </style>
</head>

<body>
    <h1>Login</h1>
    <form action="login.php" id="loginForm">
        <label for="username">Username:</label>
        <input type="text" id="username" name="username" required><br><br>

        <label for="password">Password:</label>
        <input type="password" id="password" name="password" required><br><br>

        <input type="submit" value="Login">
    </form>

    <script>
        document.getElementById("loginForm").addEventListener("submit", function(event) {
            event.preventDefault(); // Prevent the default form submission

            // Get the input values
            var username = document.getElementById("username").value;
            var password = document.getElementById("password").value;

            // Create a new FormData object and append the username and password
            var formData = new FormData();
            formData.append("username", username);
            formData.append("password", password);

            // Send a POST request to login.php
            fetch("login.php", {
                    method: "POST",
                    body: formData
                })
                .then(response => response.json()) // Assuming the response from login.php is in JSON format
                .then(data => {
                    // Handle the response data here (e.g., show a success message or error message)
                    // console.log(data);
                    alert(data["message"]);
                })
                .catch(error => {
                    console.error("Error:", error);
                });
        });
    </script>
</body>

</html>