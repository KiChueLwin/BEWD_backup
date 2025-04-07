<?php
session_start();
include("database/db_connection.php");

if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_SESSION['user_id'])) {
    $recipe_id = $_POST['recipe_id'];
    $user_id = $_SESSION['user_id'];
    $rating = $_POST['rating'];

    // Sanitize the rating input
    $rating = filter_var($rating, FILTER_SANITIZE_NUMBER_INT);

    // Validate the rating
    if ($rating >= 1 && $rating <= 5) {
        $stmt = $conn->prepare("INSERT INTO ratings (recipe_id, user_id, rating) VALUES (?, ?, ?)");
        $stmt->bind_param("iii", $recipe_id, $user_id, $rating);

        if ($stmt->execute()) {
            // Rating added successfully
        } else {
            // Error adding rating
            echo "Error: " . $stmt->error;
        }

        $stmt->close();
    } else {
        echo "Invalid rating.";
    }
}

$conn->close();
header("Location: community-cookbook.php"); // Redirect back
exit();
?>