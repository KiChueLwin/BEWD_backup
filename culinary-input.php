<?php
include("navigation.php");
include("database/db_connection.php");

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $title = $_POST['resource-title'];
    $type = $_POST['resource-type'];
    $description = $_POST['resource-description'];
    $cuisine_type = $_POST['cuisine-type'] ?? ''; // Set default to empty string
    $audience = $_POST['target-audience'];

    $photo = null;
    $file = null;
    $video = $_POST['video-link'] ?? null;
    $admin_id = 1; // You'll likely need to handle the admin ID dynamically based on your user system

    // Handle photo upload
    if (isset($_FILES['resource-photo']) && $_FILES['resource-photo']['error'] == UPLOAD_ERR_OK) {
        $photo_name = $_FILES['resource-photo']['name'];
        $tmp_name = $_FILES['resource-photo']['tmp_name'];
        $target_dir = "upload/";
        $target_photo = $target_dir . basename($photo_name);

        if (move_uploaded_file($tmp_name, $target_photo)) {
            $photo = $target_photo;
        } else {
            echo "<script>alert('Error uploading photo.');</script>";
        }
    }

    // Handle file upload
    if (isset($_FILES['resource-file']) && $_FILES['resource-file']['error'] == UPLOAD_ERR_OK) {
        $file_name = $_FILES['resource-file']['name'];
        $tmp_name = $_FILES['resource-file']['tmp_name'];
        $target_dir = "upload/";
        $target_file = $target_dir . basename($file_name);

        if (move_uploaded_file($tmp_name, $target_file)) {
            $file = $target_file;
        } else {
            echo "<script>alert('Error uploading file.');</script>";
        }
    }

    // Prepare and execute the SQL query
    $stmt = $conn->prepare("INSERT INTO culinary_resources (title, type, description, cuisine_type, audience, photo, file, video, admin_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
    $stmt->bind_param("ssssssssi", $title, $type, $description, $cuisine_type, $audience, $photo, $file, $video, $admin_id);

    if ($stmt->execute()) {
        echo "<script>alert('Culinary Resource added successfully.');</script>";
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
    <title>Culinary Resources Input</title>
    <link rel="stylesheet" href="bootstrap/css/bootstrap.min.css">
    <style>
        body {
            font-family: sans-serif;
            background-color: #f8f9fa;
            margin: 0;
            padding: 0;
        }

        .sidebar {
            width: 200px;
            background-color: #343a40;
            color: white;
            padding: 20px;
            height: 100vh;
        }

        .sidebar a {
            color: white;
            text-decoration: none;
            display: block;
            margin-bottom: 10px;
        }

        .content {
            flex: 1;
            padding: 20px;
            background-color: white;
            border-radius: 8px;
            margin: 20px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }

        .content h2 {
            color: #dc3545;
            margin-bottom: 20px;
        }

        .form-group {
            margin-bottom: 20px;
        }

        label {
            display: block;
            margin-bottom: 5px;
        }

        input[type="text"],
        textarea,
        select,
        input[type="file"] {
            width: 100%;
            padding: 8px;
            border: 1px solid #ced4da;
            border-radius: 4px;
            box-sizing: border-box;
        }

        button[type="submit"] {
            background-color: #dc3545;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }

        button[type="submit"]:hover {
            background-color: #c82333;
        }
    </style>
</head>

<body>
    <div class="content">
        <h2>Culinary Resources Input</h2>
        <form method="POST" enctype="multipart/form-data">
            <div class="form-group">
                <label for="resource-title">Resource Title:</label>
                <input type="text" id="resource-title" name="resource-title" required>
            </div>
            <div class="form-group">
                <label for="resource-type">Resource Type:</label>
                <select id="resource-type" name="resource-type" required>
                    <option value="">Select Type</option>
                    <option value="Recipe Card">Recipe Card</option>
                    <option value="Cooking Tutorial">Cooking Tutorial</option>
                    <option value="Instructional Video">Instructional Video</option>
                    <option value="Kitchen Hack">Kitchen Hack</option>
                    <option value="Downloadable Recipe">Downloadable Recipe</option>
                    <option value="Other">Other</option>
                </select>
            </div>
            <div class="form-group">
                <label for="resource-description">Description:</label>
                <textarea id="resource-description" name="resource-description" rows="4" required></textarea>
            </div>
            <div class="form-group">
                <label for="cuisine-type">Cuisine Type:</label>
                <input type="text" id="cuisine-type" name="cuisine-type">
            </div>
            <div class="form-group">
                <label for="target-audience">Target Audience:</label>
                <select id="target-audience" name="target-audience" required>
                    <option value="">Select Audience</option>
                    <option value="Beginner">Beginner</option>
                    <option value="Intermediate">Intermediate</option>
                    <option value="Advanced">Advanced</option>
                </select>
            </div>
            <div class="form-group">
                <label for="resource-photo">Photo:</label>
                <input type="file" id="resource-photo" name="resource-photo">
            </div>
            <div class="form-group">
                <label for="resource-file">File (Recipe/Video):</label>
                <input type="file" id="resource-file" name="resource-file">
            </div>
            <div class="form-group">
                <label for="video-link">Video Link (Optional):</label>
                <input type="text" id="video-link" name="video-link">
            </div>
            <button type="submit">Submit Culinary Resource</button>
        </form>
    </div>

    <?php
        include("footer.php");
    ?>

    <script src="bootstrap/js/bootstrap.bundle.min.js"></script>
</body>

</html>