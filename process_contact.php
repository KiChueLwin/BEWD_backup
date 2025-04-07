<?php
include 'database/db_connection.php'; // Adjust path if needed

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $name = $_POST["name"];
    $email = $_POST["email"];
    $message = $_POST["message"];

    try {
        // Assuming $conn is your mysqli connection object
        $stmt = $conn->prepare("INSERT INTO contact (name, email, message) VALUES (?, ?, ?)");
        $stmt->bind_param("sss", $name, $email, $message); // Data types specified
        $stmt->execute();

        echo "<script>alert('Message sent successfully!'); window.location.href='contactus.php';</script>";
        exit();

    } catch (mysqli_sql_exception $e) {
        echo "<script>alert('Error: " . $e->getMessage() . "'); window.location.href='contactus.php';</script>";
        exit();
    }

} else {
    header("Location: contactus.php");
    exit();
}
?>