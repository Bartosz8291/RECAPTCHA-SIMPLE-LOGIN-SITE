<?php
session_start();
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Google reCAPTCHA secret key
    $secretKey '6LcUTwQqAAAAAKsPT_9HYEgC0cAdmPV2SD00_oMs';
    
    // Verify the reCAPTCHA response
    $recaptchaResponse = $_POST['g-recaptcha-response'];
    $remoteIp = $_SERVER['REMOTE_ADDR'];
    $recaptchaUrl = "https://www.google.com/recaptcha/api/siteverify";

    $recaptcha = file_get_contents($recaptchaUrl . "?secret=" . $secretKey . "&response=" . $recaptchaResponse . "&remoteip=" . $remoteIp);
    $recaptchaData = json_decode($recaptcha);

    if ($recaptchaData->success) {
        // reCAPTCHA verified successfully
        $username = $_POST['username'];
        $password = $_POST['password'];

        // Database connection
        $servername = "localhost"; // Change this to your database server
        $dbname = "RecaptchaLoginDB"; // Change this to your database name
        $dbUsername = "admin"; // Change this to your database username
        $dbPassword = "pass82"; // Change this to your database password

        $conn = new mysqli($servername, $dbUsername, $dbPassword, $dbname);

        if ($conn->connect_error) {
            die("Connection failed: " . $conn->connect_error);
        }

        // Check if username exists
        $stmt = $conn->prepare("SELECT id, password FROM users WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $stmt->store_result();
        if ($stmt->num_rows > 0) {
            $stmt->bind_result($id, $hashedPassword);
            $stmt->fetch();
            if (password_verify($password, $hashedPassword)) {
                // Password is correct, start a session
                $_SESSION['userid'] = $id;
                $_SESSION['username'] = $username;
                header("Location: /protected_page.php");
                exit();
            } else {
                echo "Invalid username or password!";
            }
        } else {
            echo "Invalid username or password!";
        }
        $stmt->close();
        $conn->close();
    } else {
        // reCAPTCHA verification failed
        echo "reCAPTCHA verification failed. Please try again.";
    }
} else {
    // If the form is not submitted via POST, redirect back to the login page
    header("Location: /index.html");
    exit();
}
?>
