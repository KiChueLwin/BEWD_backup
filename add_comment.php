<?php
session_start();
include("database/db_connection.php");

if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_SESSION['user_id'])) {
    $recipe_id = $_POST['recipe_id'];
    $user_id = $_SESSION['user_id'];
    $comment_text = $_POST['comment_text'];

    // Sanitize the comment text
    $comment_text = htmlspecialchars(trim($comment_text));

    $stmt = $conn->prepare("INSERT INTO comments (recipe_id, user_id, comment_text) VALUES (?, ?, ?)");
    $stmt->bind_param("iis", $recipe_id, $user_id, $comment_text);

    if ($stmt->execute()) {
        // Comment added successfully
    } else {
        // Error adding comment
        echo "Error: " . $stmt->error;
    }

    $stmt->close();
}

$conn->close();
header("Location: community-cookbook.php"); // Redirect back
exit();
?>