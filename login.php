<?php
// Initialize the session.
session_start();

// Check if the user is already logged in. If yes, then redirect them to the welcome page.
if(isset($_SESSION["loggedin"]) && $_SESSION["loggedin"] === true){
    header("location: welcome.php");
    exit;
}

// Include config file.
require_once "config.php";

// Define variables and initialize with empty strings.
$username = $password = "";
$username_err = $password_err = "";

// Processing form data when form is submitted.
if($_SERVER["REQUEST_METHOD"] == "POST"){

    $user = $_POST['username'];
    $pass = $_POST['password'];

    // *Revised*: Use prepared statements to prevent SQL injection.
    // Explanation: The old code used direct string concatenation to build SQL queries, which made it vulnerable
    // to SQL injection attacks where an attacker could manipulate the SQL query. Using a prepared statement
    // ensures that the inputs are treated as data and not executable code, preventing SQL injection.
    $sql = "SELECT id, username, password FROM users_table WHERE username = ?";
    if($stmt = mysqli_prepare($link, $sql)){
        mysqli_stmt_bind_param($stmt, "s", $param_username);
        $param_username = $user;

        if(mysqli_stmt_execute($stmt)){
            mysqli_stmt_store_result($stmt);

            // Check if username exists, if yes then verify password.
            if(mysqli_stmt_num_rows($stmt) == 1){                    
                mysqli_stmt_bind_result($stmt, $id, $username, $hashed_password);
                if(mysqli_stmt_fetch($stmt)){
                    // *Revised*: Verify password using password_verify() against the stored hash.
                    // Explanation: The old code directly compared the entered password with the stored password,
                    // which was insecure if passwords were stored in plaintext. Using password_verify() ensures 
                    // that passwords are securely hashed and compared, mitigating the risk of password exposure.
                    if(password_verify($pass, $hashed_password)){
                        
                        // *Revised*: Regenerate session ID to prevent session hijacking.
                        // Vulnerability Mitigated: Session Hijacking
                        // Explanation: Regenerating the session ID upon login prevents session fixation attacks 
                        // where an attacker could use a known session ID to hijack a user's session.
                        session_regenerate_id(true);

                        // Store data in session variables.
                        $_SESSION["loggedin"] = true;
                        $_SESSION["id"] = $id;
                        $_SESSION["username"] = $username;
                        $_SESSION["display_username"] = $username;

                        // Redirect user to welcome page.
                        header("location: welcome.php");
                    } else{
                        $password_err = "The password you entered was not valid.";
                    }
                }
            } else{
                $username_err = "No account found with that username.";
            }
        } else{
            echo "Oops! Something went wrong. Please try again later.";
        }
    }

    // Close statement.
    mysqli_stmt_close($stmt);

    // Close connection.
    mysqli_close($link);
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login</title>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.css">
    <style type="text/css">
        body{ font: 14px sans-serif; }
        .wrapper{ width: 350px; padding: 20px; }
    </style>
</head>
<body>
    <div class="wrapper">
        <h1>Welcome to OnePhoto!</h1>
        <h2>Login</h2>
        <p>Please fill in your credentials to login.</p>
        <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
            <div class="form-group <?php echo (!empty($username_err)) ? 'has-error' : ''; ?>">
                <label>Username</label>
                <input type="text" name="username" class="form-control" value="<?php echo $username; ?>">
                <span class="help-block"><?php echo $username_err; ?></span>
            </div>
            <div class="form-group <?php echo (!empty($password_err)) ? 'has-error' : ''; ?>">
                <label>Password</label>
                <input type="password" name="password" class="form-control">
                <span class="help-block"><?php echo $password_err; ?></span>
            </div>
            <div class="form-group">
                <input type="submit" class="btn btn-primary" value="Login">
            </div>
            <p>Don't have an account? <a href="index.php">Sign up now</a>.</p>
        </form>
    </div>
</body>
</html>
