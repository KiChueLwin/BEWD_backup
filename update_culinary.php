<?php
session_start();
include("database/db_connection.php");

// Check if the user is logged in
if (!isset($_SESSION['admin_id'])) {
    header("Location: admin-login.php");
    exit;
}

// Retrieve admin ID from session (if needed)
$adminId = $_SESSION['admin_id'];

// Retrieve admin name from the database (if needed for display)
$adminName = "";
try {
    $stmtAdmin = $conn->prepare("SELECT name FROM admin WHERE admin_id = ?");
    $stmtAdmin->bind_param("i", $adminId);
    if ($stmtAdmin->execute()) {
        $resultAdmin = $stmtAdmin->get_result();
        if ($resultAdmin->num_rows > 0) {
            $rowAdmin = $resultAdmin->fetch_assoc();
            $adminName = $rowAdmin['name'];
        }
    }
    $stmtAdmin->close();
} catch (Exception $e) {
    // Handle error if needed
}

// Get the culinary resource ID from the URL
$culinaryId = isset($_GET['id']) ? $_GET['id'] : null;
$culinaryData = null;

if ($culinaryId) {
    try {
        $stmt = $conn->prepare("SELECT * FROM culinary_resources WHERE culinary_id = ?");
        $stmt->bind_param("i", $culinaryId);

        if ($stmt->execute()) {
            $result = $stmt->get_result();
            if ($result->num_rows > 0) {
                $culinaryData = $result->fetch_assoc();
            }
        } else {
            throw new Exception("Error retrieving culinary resource data: " . $stmt->error);
        }
        $stmt->close();
    } catch (Exception $e) {
        echo "<script>alert('Database error: " . $e->getMessage() . "');</script>";
    }
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $title = $_POST['resource-title'];
    $type = $_POST['resource-type'];
    $description = $_POST['resource-description'];
    $cuisine_type = $_POST['cuisine-type'] ?? '';
    $audience = $_POST['target-audience'];

    $photo_path = isset($culinaryData['photo']) ? $culinaryData['photo'] : null;
    $file_path = isset($culinaryData['file']) ? $culinaryData['file'] : null;
    $video_link = $_POST['video-link'] ?? null;

    // Handle photo upload
    if (isset($_FILES['resource-photo']) && $_FILES['resource-photo']['error'] == UPLOAD_ERR_OK) {
        $photo_name = $_FILES['resource-photo']['name'];
        $tmp_name = $_FILES['resource-photo']['tmp_name'];
        $target_dir = "upload/";
        $target_photo = $target_dir . basename($photo_name);

        if (move_uploaded_file($tmp_name, $target_photo)) {
            $photo_path = $target_photo;
        } else {
            $error_code = $_FILES['resource-photo']['error'];
            $upload_errors = array(
                UPLOAD_ERR_OK => 'There is no error, the file uploaded with success.',
                UPLOAD_ERR_INI_SIZE => 'The uploaded file exceeds the upload_max_filesize directive in php.ini.',
                UPLOAD_ERR_FORM_SIZE => 'The uploaded file exceeds the MAX_FILE_SIZE directive that was specified in the HTML form.',
                UPLOAD_ERR_PARTIAL => 'The uploaded file was only partially uploaded.',
                UPLOAD_ERR_NO_FILE => 'No file was uploaded.',
                UPLOAD_ERR_NO_TMP_DIR => 'Missing a temporary folder.',
                UPLOAD_ERR_CANT_WRITE => 'Failed to write file to disk.',
                UPLOAD_ERR_EXTENSION => 'A PHP extension stopped the file upload.',
            );
            $error_message = isset($upload_errors[$error_code]) ? $upload_errors[$error_code] : 'Unknown upload error.';
            echo "<script>alert('Error uploading new photo: " . $error_message . "');</script>";
        }
    }

    // Handle file upload
    if (isset($_FILES['resource-file']) && $_FILES['resource-file']['error'] == UPLOAD_ERR_OK) {
        $file_name = $_FILES['resource-file']['name'];
        $tmp_name = $_FILES['resource-file']['tmp_name'];
        $target_dir = "upload/";
        $target_file = $target_dir . basename($file_name);

        if (move_uploaded_file($tmp_name, $target_file)) {
            $file_path = $target_file;
        } else {
            $error_code = $_FILES['resource-file']['error'];
            $upload_errors = array(
                UPLOAD_ERR_OK => 'There is no error, the file uploaded with success.',
                UPLOAD_ERR_INI_SIZE => 'The uploaded file exceeds the upload_max_filesize directive in php.ini.',
                UPLOAD_ERR_FORM_SIZE => 'The uploaded file exceeds the MAX_FILE_SIZE directive that was specified in the HTML form.',
                UPLOAD_ERR_PARTIAL => 'The uploaded file was only partially uploaded.',
                UPLOAD_ERR_NO_FILE => 'No file was uploaded.',
                UPLOAD_ERR_NO_TMP_DIR => 'Missing a temporary folder.',
                UPLOAD_ERR_CANT_WRITE => 'Failed to write file to disk.',
                UPLOAD_ERR_EXTENSION => 'A PHP extension stopped the file upload.',
            );
            $error_message = isset($upload_errors[$error_code]) ? $upload_errors[$error_code] : 'Unknown upload error.';
            echo "<script>alert('Error uploading new file: " . $error_message . "');</script>";
        }
    }

    if ($culinaryId) {
        $stmt = $conn->prepare("UPDATE culinary_resources SET title = ?, type = ?, description = ?, cuisine_type = ?, audience = ?, photo = ?, file = ?, video = ? WHERE culinary_id = ?");
        $stmt->bind_param("ssssssssi", $title, $type, $description, $cuisine_type, $audience, $photo_path, $file_path, $video_link, $culinaryId);
    }

    if (isset($stmt) && $stmt->execute()) {
        echo "<script>alert('Culinary Resource updated successfully.');</script>";
    } elseif (isset($stmt)) {
        echo "<script>alert('Error updating culinary resource: " . $stmt->error . "');</script>";
    }

    if (isset($stmt)) {
        $stmt->close();
    }
    $conn->close();
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Update Culinary Resource</title>
    <link rel="stylesheet" href="bootstrap/css/bootstrap.min.css">
    <link rel="stylesheet" href="css/admin.css?<?php echo time(); ?>">
    <style>
        body {
            background-color: white;
        }
    </style>
</head>

<body>
    <?php include("navigation.php"); ?>

    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
    </nav>

    <div class="dashboard-container">
        <main class="main-content">
            <header class="header">
                <a href="admin_dashboard.php" class="user-profile-link">
                    <div class="user-profile">
                        <img src="image/user_avatar.png" alt="User Avatar">
                        <span class="admin-name"><?php echo $adminName; ?></span>
                    </div>
                </a>
            </header>
            <section class="content">
                <h2><?php echo $culinaryId ? 'Update Culinary Resource' : 'Add New Culinary Resource'; ?></h2>
                <?php if ($culinaryId && !$culinaryData): ?>
                    <div class="alert alert-danger" role="alert">
                        Culinary resource not found.
                    </div>
                <?php else: ?>
                    <form class="recipe-import-form" method="POST" enctype="multipart/form-data">
                        <div class="form-group">
                            <label for="resource-title">Title:</label>
                            <input type="text" class="form-control" id="resource-title" name="resource-title"
                                value="<?php echo isset($culinaryData['title']) ? htmlspecialchars($culinaryData['title']) : ''; ?>"
                                required>
                        </div>

                        <div class="form-group">
                            <label for="resource-type">Resource Type:</label>
                            <select class="form-control" id="resource-type" name="resource-type" required>
                                <option value="">Select Type</option>
                                <option value="Recipe Card" <?php if (isset($culinaryData['type']) && $culinaryData['type'] == 'Recipe Card')
                                    echo 'selected'; ?>>Recipe Card</option>
                                <option value="Cooking Tutorial" <?php if (isset($culinaryData['type']) && $culinaryData['type'] == 'Cooking Tutorial')
                                    echo 'selected'; ?>>Cooking Tutorial</option>
                                <option value="Instructional Video" <?php if (isset($culinaryData['type']) && $culinaryData['type'] == 'Instructional Video')
                                    echo 'selected'; ?>>Instructional Video
                                </option>
                                <option value="Kitchen Hack" <?php if (isset($culinaryData['type']) && $culinaryData['type'] == 'Kitchen Hack')
                                    echo 'selected'; ?>>Kitchen Hack</option>
                                <option value="Downloadable Recipe" <?php if (isset($culinaryData['type']) && $culinaryData['type'] == 'Downloadable Recipe')
                                    echo 'selected'; ?>>Downloadable Recipe
                                </option>
                                <option value="Other" <?php if (isset($culinaryData['type']) && $culinaryData['type'] == 'Other')
                                    echo 'selected'; ?>>Other</option>
                            </select>
                        </div>

                        <div class="form-group">
                            <label for="resource-description">Description:</label>
                            <textarea class="form-control" id="resource-description" name="resource-description" rows="4"
                                required><?php echo isset($culinaryData['description']) ? htmlspecialchars($culinaryData['description']) : ''; ?></textarea>
                        </div>

                        <div class="form-group">
                            <label for="cuisine-type">Cuisine Type:</label>
                            <input type="text" class="form-control" id="cuisine-type" name="cuisine-type"
                                value="<?php echo isset($culinaryData['cuisine_type']) ? htmlspecialchars($culinaryData['cuisine_type']) : ''; ?>">
                        </div>

                        <div class="form-group">
                            <label for="target-audience">Target Audience:</label>
                            <select class="form-control" id="target-audience" name="target-audience" required>
                                <option value="">Select Audience</option>
                                <option value="Beginner" <?php if (isset($culinaryData['audience']) && $culinaryData['audience'] == 'Beginner')
                                    echo 'selected'; ?>>Beginner</option>
                                <option value="Intermediate" <?php if (isset($culinaryData['audience']) && $culinaryData['audience'] == 'Intermediate')
                                    echo 'selected'; ?>>Intermediate</option>
                                <option value="Advanced" <?php if (isset($culinaryData['audience']) && $culinaryData['audience'] == 'Advanced')
                                    echo 'selected'; ?>>Advanced</option>
                            </select>
                        </div>

                        <div class="form-group">
                            <label for="resource-photo">Photo:</label>
                            <input type="file" class="form-control-file" id="resource-photo" name="resource-photo">
                            <?php if (isset($culinaryData['photo']) && !empty($culinaryData['photo'])): ?>
                                <p>Current Photo:</p>
                                <img src="<?php echo htmlspecialchars($culinaryData['photo']); ?>" alt="Current Photo"
                                    style="max-width: 100px;">
                            <?php endif; ?>
                        </div>

                        <div class="form-group">
                            <label for="resource-file">File (Recipe/Video):</label>
                            <input type="file" class="form-control-file" id="resource-file" name="resource-file">
                            <?php if (isset($culinaryData['file']) && !empty($culinaryData['file'])): ?>
                                <p>Current File: <a href="<?php echo htmlspecialchars($culinaryData['file']); ?>"
                                        target="_blank">View File</a></p>
                            <?php endif; ?>
                        </div>

                        <div class="form-group">
                            <label for="video-link">Video Link (Optional):</label>
                            <input type="text" class="form-control" id="video-link" name="video-link"
                                value="<?php echo isset($culinaryData['video']) ? htmlspecialchars($culinaryData['video']) : ''; ?>">
                        </div>

                        <button type="submit"
                            class="btn btn-primary"><?php echo $culinaryId ? 'Update Resource' : 'Add New Resource'; ?></button>
                        <a href="culinary_resources_collection.php" class="btn btn-secondary ml-2">Back to List</a>
                    </form>
                <?php endif; ?>
            </section>
        </main>
    </div>

    <?php include('footer.php'); ?>

    <script src="bootstrap/js/bootstrap.bundle.min.js"></script>
</body>

</html>