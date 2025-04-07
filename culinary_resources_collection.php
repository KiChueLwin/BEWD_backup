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

try {
    $stmt = $conn->prepare("SELECT name FROM admin WHERE admin_id = ?");
    $stmt->bind_param("i", $adminId);

    if ($stmt->execute()) {
        $result = $stmt->get_result();
        if ($result->num_rows > 0) {
            $row = $result->fetch_assoc();
            $adminName = $row['name'];
        }
    } else {
        throw new Exception("Error retrieving admin name: " . $stmt->error);
    }
    $stmt->close();
} catch (Exception $e) {
    $message = "Database error: " . $e->getMessage();
    $messageClass = "alert-danger";
}

// Handle delete action
if (isset($_GET['delete_id'])) {
    $deleteId = $_GET['delete_id'];
    $deleteQuery = "DELETE FROM culinary_resources WHERE culinary_id = ?";
    $deleteStmt = mysqli_prepare($conn, $deleteQuery);
    mysqli_stmt_bind_param($deleteStmt, "i", $deleteId);

    if (mysqli_stmt_execute($deleteStmt)) {
        header("Location: culinary_resources_collection.php"); // Redirect after successful deletion
        exit;
    } else {
        echo "Error deleting resource: " . mysqli_error($conn);
    }
    mysqli_stmt_close($deleteStmt);
}

// Fetch culinary resources data (without pagination as per your request)
$sql = "SELECT * FROM culinary_resources";
$culinaryResult = $conn->query($sql);
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Culinary Resources Collection</title>
    <link rel="stylesheet" href="bootstrap/css/bootstrap.min.css">
    <link rel="stylesheet" href="css/admin.css?<?php echo time(); ?>">
    <style>
        .recipe-photo {
            max-width: 100px;
            max-height: 100px;
        }
    </style>
</head>

<body>

    <?php include("navigation.php"); ?>

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
                <h2>Culinary Resources Collection</h2>
                <table class="table">
                    <thead>
                        <tr>
                            <th>Admin_ID</th>
                            <th>Culinary_ID</th>
                            <th>Title</th>
                            <th>Type</th>
                            <th>Cuisine Type</th>
                            <th>Audience</th>
                            <th>Photo</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php
                        if ($culinaryResult->num_rows > 0) {
                            while ($row = $culinaryResult->fetch_assoc()) {
                                echo "<tr>";
                                echo "<td>" . htmlspecialchars($row['admin_id']) . "</td>";
                                echo "<td>" . htmlspecialchars($row['culinary_id']) . "</td>";
                                echo "<td>" . htmlspecialchars($row['title']) . "</td>";
                                echo "<td>" . htmlspecialchars($row['type']) . "</td>";
                                echo "<td>" . htmlspecialchars($row['cuisine_type']) . "</td>";
                                echo "<td>" . htmlspecialchars($row['audience']) . "</td>";
                                echo "<td>";
                                if (!empty($row['photo'])) {
                                    echo "<img src='" . htmlspecialchars($row['photo']) . "' alt='" . htmlspecialchars($row['title']) . " Photo' class='recipe-photo'>";
                                } else {
                                    echo "No Photo";
                                }
                                echo "</td>";
                                echo "<td>
                                        <a href='update_culinary.php?id=" . $row['culinary_id'] . "' class='btn btn-primary btn-sm'>Update</a>
                                        <a href='culinary_resources_collection.php?delete_id=" . $row['culinary_id'] . "' class='btn btn-danger btn-sm'>Delete</a>
                                    </td>";
                                echo "</tr>";
                            }
                        } else {
                            echo "<tr><td colspan='7'>No culinary resources found.</td></tr>";
                        }
                        ?>
                    </tbody>
                </table>
            </section>
        </main>
    </div>

    <?php include("footer.php"); ?>

    <script src="bootstrap/js/bootstrap.bundle.min.js"></script>
</body>

</html>