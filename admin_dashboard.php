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

// Count Users
$users_query = "SELECT COUNT(*) FROM users";
$users_result = mysqli_query($conn, $users_query);
$users_count = mysqli_fetch_array($users_result)[0];

// Count Resources
$resources_query = "SELECT COUNT(*) FROM edu_resources";
$resources_result = mysqli_query($conn, $resources_query);
$resources_count = mysqli_fetch_array($resources_result)[0];

// Count Recipes
$recipes_query = "SELECT COUNT(*) FROM recipe";
$recipes_result = mysqli_query($conn, $recipes_query);
$recipes_count = mysqli_fetch_array($recipes_result)[0];

// Count Community
$recipes_query = "SELECT COUNT(*) FROM community_recipes";
$recipes_result = mysqli_query($conn, $recipes_query);
$community_count = mysqli_fetch_array($recipes_result)[0];

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard</title>
    <link rel="stylesheet" href="bootstrap/css/bootstrap.min.css">
    <link rel="stylesheet" href="css/admin.css?<?php echo time(); ?>">
</head>
<body>

    

    <div class="dashboard-container">
        <aside class="sidebar">
            <nav class="nav">
                <a href="admin_dashboard.php" class="active">Dashboard</a>
                <a href="recipe-input.php">Input Recipes</a>
                <a href="recipes_collection.php">Recipes Collection</a>
                
                <a href="edu-resources-input.php">Input Education Resources</a>
                <a href="edu-resources-collection.php">Education Resources Collection</a>
                <a href="culinary-input.php">Input Culinary Resources</a>
                <a href="culinary_resources_collection.php">Culinary Resources Collection</a>
                
                <a href="community-cookbook-collection.php">Community Cookbook</a>
                <a href="members_info.php">Members Information </a>
                <a href="contact-messages.php">View Messages </a>
                <a href="admin-welcome.php">Home Page</a>

                
                <a href="home1.php">Log out </a>
            </nav>
        </aside>
        <main class="main-content">
            <header class="header">
                <div class="user-profile">
                    <img src="image/user_avatar.png" alt="User Avatar">
                    <span class="admin-name"><?php echo $adminName; ?></span>
                </div>
            </header>
            <section class="content">
                <div class="stats-container">
                    <div class="stat-box">
                        <div class="stat-value"><?php echo $users_count; ?></div>
                        <div class="stat-label">Members</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value"><?php echo $resources_count; ?></div>
                        <div class="stat-label">Resources</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value"><?php echo $recipes_count; ?></div>
                        <div class="stat-label">Recipes</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value"><?php echo $community_count; ?></div>
                        <div class="stat-label">Community Cookbook</div>
                    </div>
                </div>
            </section>
        </main>
    </div>

    
</body>
</html>