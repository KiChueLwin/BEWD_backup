<?php
session_start(); // Start the session

include 'database/db_connection.php'; // Assuming this file establishes the $conn connection

$message = "";
$messageClass = "";

$max_attempts = 3;
$lockout_time = 180; // 3 minutes in seconds

$login_attempts = isset($_COOKIE['login_attempts']) ? (int)$_COOKIE['login_attempts'] : 0;
$last_attempt_time = isset($_COOKIE['last_attempt_time']) ? (int)$_COOKIE['last_attempt_time'] : 0;

$remaining_time = 0;

if ($login_attempts >= $max_attempts) {
    $remaining_time = max(0, $lockout_time - (time() - $last_attempt_time));
    if ($remaining_time > 0) {
        $minutes = ceil($remaining_time / 60);
        $seconds = $remaining_time % 60;
        $formatted_time = sprintf("%02d:%02d", $minutes, $seconds);
        $message = "Try again in <span id='countdown'>" . $formatted_time . "</span> minutes.";
        $messageClass = "alert-danger";
    } else {
        setcookie('login_attempts', 0, time() + $lockout_time, "/");
        setcookie('last_attempt_time', 0, time() + $lockout_time, "/");
        $login_attempts = 0;
        $last_attempt_time = 0;
    }
}

if (isset($_POST['submit']) && $login_attempts < $max_attempts) {
    $email = $_POST['email'];
    $pwd = $_POST['password'];

    try {
        $stmt = $conn->prepare("SELECT * FROM admin WHERE email = ?");
        if (!$stmt) {
            throw new Exception("Database error: " . $conn->error);
        }

        $stmt->bind_param("s", $email);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows == 1) {
            $record = $result->fetch_assoc();
            $stored_pw = $record['password'];

            if ($pwd === $stored_pw) {
                $_SESSION['admin_id'] = $record['admin_id'];
                $_SESSION['email'] = $record['email'];
                $message = "Login successful!";
                $messageClass = "alert-success";
                echo "<script>window.location.href='admin-welcome.php'</script>";
                exit;
            } else {
                $login_attempts++;
                setcookie('login_attempts', $login_attempts, time() + $lockout_time, "/");
                setcookie('last_attempt_time', time(), time() + $lockout_time, "/");

                $remaining_attempts = $max_attempts - $login_attempts;
                $message = "Invalid Password! You have " . $remaining_attempts . " attempts left.";
                $messageClass = "alert-warning";
            }
        } else {
            $login_attempts++;
            setcookie('login_attempts', $login_attempts, time() + $lockout_time, "/");
            setcookie('last_attempt_time', time(), time() + $lockout_time, "/");

            $remaining_attempts = $max_attempts - $login_attempts;
            $message = "Your email is invalid! You have " . $remaining_attempts . " attempts left.";
            $messageClass = "alert-warning";
        }
        $stmt->close();
    } catch (Exception $e) {
        $message = "An error occurred: " . $e->getMessage();
        $messageClass = "alert-danger";
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <link rel="stylesheet" href="bootstrap/css/bootstrap.min.css">
    <link rel="stylesheet" href="css/login.css?<?php echo time(); ?>">
</head>
<body>
    <?php include("navigation.php"); ?>

    <div class="container">
        <div class="login-form">
            <h2>Login</h2>
            <?php if ($message): ?>
                <div class="alert <?php echo $messageClass; ?>" role="alert">
                    <?php echo $message; ?>
                </div>
            <?php endif; ?>
            <form action="admin-login.php" method="post">
                <label for="email">Email:</label>
                <input type="email" id="email" name="email">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password">
                <button type="submit" name="submit" <?php echo ($login_attempts >= $max_attempts) ? 'disabled' : ''; ?>>Login</button>
                <p class="text-center mt-3">
                    <a href="register-form.php">Create Account</a> | <a href="resetpassword.php">Forgot Password</a>
                </p>
            </form>
        </div>
    </div>

    <?php if ($remaining_time > 0): ?>
    <script>
        function startTimer(duration, display) {
            var timer = duration, minutes, seconds;
            setInterval(function () {
                minutes = parseInt(timer / 60, 10);
                seconds = parseInt(timer % 60, 10);

                minutes = minutes < 10 ? "0" + minutes : minutes;
                seconds = seconds < 10 ? "0" + seconds : seconds;

                display.textContent = minutes + ":" + seconds;

                if (--timer < 0) {
                    window.location.reload();
                }
            }, 1000);
        }

        window.onload = function () {
            var duration = <?php echo $remaining_time; ?>;
            var display = document.querySelector('#countdown');
            startTimer(duration, display);
        };
    </script>
    <?php endif; ?>
</body>
</html>