<?php
// Replace with your secret key
$secretKey = "YOUR_SECRET_KEY";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $name = $_POST["name"];
    $email = $_POST["email"];
    $message = $_POST["message"];
    $recaptchaResponse = $_POST["g-recaptcha-response"]; // Change to this

    // Verify reCAPTCHA
    $url = 'https://www.google.com/recaptcha/api/siteverify';
    $data = [
        'secret' => $secretKey,
        'response' => $recaptchaResponse,
    ];

    $options = [
        'http' => [
            'header' => "Content-type: application/x-www-form-urlencoded\r\n",
            'method' => 'POST',
            'content' => http_build_query($data),
        ],
    ];

    $context = stream_context_create($options);
    $verify = file_get_contents($url, false, $context);
    $captcha_success = json_decode($verify);

    if ($captcha_success->success == true) { // Remove score check
        // reCAPTCHA verification successful. Proceed with sending email.
        $to = "your_email@example.com"; // Replace with your email address
        $subject = "Contact Form Submission";
        $body = "Name: " . $name . "\nEmail: " . $email . "\nMessage: " . $message;
        $headers = "From: " . $email;

        if (mail($to, $subject, $body, $headers)) {
            echo "Thank you for your message!";
        } else {
            echo "Sorry, there was a problem sending your message.";
        }
    } else {
        // reCAPTCHA verification failed.
        echo "reCAPTCHA verification failed. Please try again.";
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Contact Us - Food Fusion</title>
    <link rel="stylesheet" href="bootstrap/css/bootstrap.min.css">
    <link rel="stylesheet" href="css/contactus.css?<?php echo time(); ?>">
    
    <script src="https://www.google.com/recaptcha/api.js" async defer></script>
</head>
<body>
    <?php include("navigation.php"); ?>

    <section class="contact-section">
        <div class="container">
            <div class="contact-content">
                <div class="contact-info">
                    <h2>About Food Fusion Hub</h2>
                    <p>Join our community to explore delicious creations, share your own culinary adventures, and connect with fellow food enthusiasts.</p>
                    <h2>Follow Us</h2>
                    <div class="social-links">
                        <a href="#"><img src="image/facebook.png" alt="Facebook"></a>
                        <a href="#"><img src="image/twitter.png" alt="Twitter"></a>
                        <a href="#"><img src="image/instagram.png" alt="Instagram"></a>
                    </div>
                </div>
                <div class="contact-form">
                    <h2>Contact Form</h2>
                    <form action="process_contact.php" method="post">
                        <input type="text" name="name" placeholder="Enter your Name" required>
                        <input type="email" name="email" placeholder="Enter a valid email address" required>
                        <textarea name="message" placeholder="Enter your message" required></textarea>
                        <div class="g-recaptcha" data-sitekey="6LdDBQYrAAAAAB3D_bM11B_5GzpwlBHKgkPWcDzh"></div>
                        <button type="submit">Submit</button>
                    </form>
                </div>
            </div>
        </div>
    </section>

    

    <script src="bootstrap/js/bootstrap.bundle.min.js"></script>
</body>

</html>