<?php
include './database/db_connection.php';

$recipe_id = $_GET['id'];

$stmt = $conn->prepare("SELECT * FROM recipe WHERE recipe_id = ?");
$stmt->bind_param("i", $recipe_id);
$stmt->execute();
$result = $stmt->get_result();
$stmt->close();

if ($result->num_rows > 0) {
    $recipe = $result->fetch_assoc();
    // Add these lines for debugging:
    echo "<pre>";
    print_r($recipe);
    echo "</pre>";

    echo "<h2>" . $recipe['name'] . "</h2>";
    echo "<img src='" . $recipe['photo'] . "' alt='Recipe Image'>";
    echo "<p><strong>Title:</strong> " . $recipe['name'] . "</p>";
    echo "<p><strong>Description:</strong> " . $recipe['description'] . "</p>";
} else {
    echo "Recipe not found.";
}

$conn->close();
?>