<?php
require_once "config.php";

// Define variables and initialize with empty values.
$username = $password = $confirm_password = "";
$username_err = $password_err = $confirm_password_err = "";

if($_SERVER["REQUEST_METHOD"] == "POST"){

    // Check if the username is available or already taken.
    if(empty(trim($_POST["username"]))){
        $username_err = "Please enter a username.";
    } else{
        // *Revised*: Use prepared statements to avoid SQL injection.
        // Explanation: Using prepared statements ensures that user input is treated as data rather than executable code,
        // thus preventing SQL injection attacks where malicious code could be injected via input fields.
        $sql = "SELECT id FROM users_table WHERE username = ?";
        if($stmt = mysqli_prepare($link, $sql)){
            mysqli_stmt_bind_param($stmt, "s", $param_username);
            $param_username = trim($_POST["username"]);

            if(mysqli_stmt_execute($stmt)){
                mysqli_stmt_store_result($stmt);
                if(mysqli_stmt_num_rows($stmt) == 1){
                    $username_err = "This username is already taken.";
                } else{
                    $username = trim($_POST["username"]);
                }
            } else{
                echo "Oops! Something went wrong. Please try again later.";
            }
        }
        mysqli_stmt_close($stmt);
    }

    // Validate password.
    if(empty(trim($_POST["password"]))){
        $password_err = "Please enter a password.";     
    } elseif(strlen(trim($_POST["password"])) < 10){
        $password_err = "Password must have at least 10 characters.";
    } else{
        $password = trim($_POST["password"]);
    }
    
    // Validate confirm password.
    if(empty(trim($_POST["confirm_password"]))){
        $confirm_password_err = "Please confirm password.";     
    } else{
        $confirm_password = trim($_POST["confirm_password"]);
        if(empty($password_err) && ($password != $confirm_password)){
            $confirm_password_err = "Password did not match.";
        }
    }

    // Check for input errors before inserting in the database.
    if(empty($username_err) && empty($password_err) && empty($confirm_password_err)){

        // *Revised*: Hash the password before storing it in the database.
        
        // Explanation: Hashing the password before storage ensures that the original password is not stored in the database,
        // reducing the risk of exposure in case the database is compromised.
        $sql = "INSERT INTO users_table (username, password) VALUES (?, ?)";
        if($stmt = mysqli_prepare($link, $sql)){
            mysqli_stmt_bind_param($stmt, "ss", $param_username, $param_password);
            $param_username = $username;
            $param_password = password_hash($password, PASSWORD_DEFAULT);  // *Revised* Using password_hash() to securely store passwords.

            if(mysqli_stmt_execute($stmt)){
                header("location: login.php");
            } else{
                echo "Something went wrong. Please try again later.";
            }
        }
        mysqli_stmt_close($stmt);
    }

    mysqli_close($link);
}
?>
