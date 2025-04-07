<?php
session_start();
include("database/db_connection.php");

// Check if the user is logged in
if (!isset($_SESSION['admin_id'])) {
    header("Location: admin-login.php");
    exit;
}

// Retrieve admin ID from session
$adminId = $_SESSION['admin_id'];

// Retrieve admin name from the database
$adminName = "";
$adminAvatar = "image/user_avatar.png"; // Default avatar

try {
    $stmt = $conn->prepare("SELECT name, avatar FROM admin WHERE admin_id = ?");
    $stmt->bind_param("i", $adminId);

    if ($stmt->execute()) {
        $result = $stmt->get_result();
        if ($result->num_rows > 0) {
            $row = $result->fetch_assoc();
            $adminName = $row['name'];
            $adminAvatar = $row['avatar']; // Retrieve avatar path
        }
    } else {
        throw new Exception("Error retrieving admin data: " . $stmt->error);
    }
    $stmt->close();
} catch (Exception $e) {
    $message = "Database error: " . $e->getMessage();
    $messageClass = "alert-danger";
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $name = $_POST['recipe-name'];
    $recipe_type = $_POST['recipe-type'];
    $description = $_POST['description'];
    $difficulty_level = $_POST['difficulty-level'];
    $dietary_preference = $_POST['dietary-preference'];
    $photo_name = $_FILES['recipe-photo']['name'];
    $tmp_name = $_FILES['recipe-photo']['tmp_name'];
    $target_file = "upload/" . $photo_name;

    copy($tmp_name, $target_file);

    $stmt = $conn->prepare("INSERT INTO recipe (name, recipe_type, description, difficulty_level, dietary_preference, photo, admin_id) VALUES (?, ?, ?, ?, ?, ?, ?)");
    $stmt->bind_param("ssssssi", $name, $recipe_type, $description, $difficulty_level, $dietary_preference, $target_file, $adminId);

    if ($stmt->execute()) {
        echo "<script>alert('Recipe added successfully.');</script>";
    } else {
        echo "<script>alert('Error: " . $stmt->error . "');</script>";
    }

    $stmt->close();
    $conn->close();
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Recipe Input</title>
    <link rel="stylesheet" href="bootstrap/css/bootstrap.min.css">
    <link rel="stylesheet" href="css/recipe-input.css?<?php echo time(); ?>">
</head>

<body>
    <div class="dashboard-container">
        <main class="main-content">
            
        <?php
        include("navigation.php");

        ?>

            <div class="content">
                <h2>Recipe Input</h2>
                <form class="recipe-import-form" method="POST" enctype="multipart/form-data">

                    <div class="form-group">
                        <label for="recipe-name">Name:</label>
                        <input type="text" id="recipe-name" name="recipe-name" required>
                    </div>

                    <div class="form-group">
                        <label for="recipe-type">Recipe Type:</label>
                        <select id="recipe-type" name="recipe-type" required>
                            <option value="">Select Cuisine</option>
                            <option value="Chinese">Chinese</option>
                            <option value="Japanese">Japanese</option>
                            <option value="Thai">Thai</option>
                            <option value="Indian">Indian</option>
                            <option value="Korean">Korean</option>
                            <option value="Italian">Italian</option>
                            <option value="French">French</option>
                            <option value="Mexican">Mexican</option>
                            <option value="American">American</option>
                            <option value="Mediterranean">Mediterranean</option>
                            <option value="Other">Other</option>
                        </select>
                    </div>

                    <div class="form-group">
                        <label for="description">Description:</label>
                        <textarea id="description" name="description" rows="4" required></textarea>
                    </div>

                    <div class="form-group">
                        <label for="difficulty-level">Difficulty Level:</label>
                        <select id="difficulty-level" name="difficulty-level" required>
                            <option value="">Select Level</option>
                            <option value="easy">Easy</option>
                            <option value="medium">Medium</option>
                            <option value="hard">Hard</option>
                        </select>
                    </div>

                    <div class="form-group">
                        <label for="dietary-preference">Dietary Preference:</label>
                        <select id="dietary-preference" name="dietary-preference" required>
                            <option value="">Select Preference</option>
                            <option value="Vegetarian">Vegetarian</option>
                            <option value="Non-Vegetarian">Non-Vegetarian</option>
                        </select>
                    </div>

                    <div class="form-group">
                        <label for="recipe-photo">Photo:</label>
                        <input type="file" id="recipe-photo" name="recipe-photo" required>
                    </div>

                    <button type="submit">Submit Recipe</button>
                </form>
            </div>
        </main>
    </div>

    <?php
        include("footer.php");

        ?>

    

    <script src="bootstrap/js/bootstrap.bundle.min.js"></script>
</body>

</html>