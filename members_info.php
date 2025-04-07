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
    $deleteQuery = "DELETE FROM users WHERE user_id = ?";
    $deleteStmt = mysqli_prepare($conn, $deleteQuery);
    mysqli_stmt_bind_param($deleteStmt, "i", $deleteId);
    if (mysqli_stmt_execute($deleteStmt)) {
        header("Location: members_info.php");
        exit;
    } else {
        echo "Error deleting record: " . mysqli_error($conn);
    }
    mysqli_stmt_close($deleteStmt);
}

// Pagination variables
$results_per_page = 7;
$query = "SELECT * FROM users";
$result = mysqli_query($conn, $query);
$number_of_results = mysqli_num_rows($result);
$number_of_pages = ceil($number_of_results / $results_per_page);

if (!isset($_GET['page'])) {
    $page = 1;
} else {
    $page = $_GET['page'];
}

$start_limit = ($page - 1) * $results_per_page;
$sql = "SELECT * FROM users LIMIT " . $start_limit . ',' . $results_per_page;
$userDataResult = mysqli_query($conn, $sql);
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Members Info</title>
    <link rel="stylesheet" href="bootstrap/css/bootstrap.min.css">
    <link rel="stylesheet" href="css/admin.css?<?php echo time(); ?>">
</head>

<body>

    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
    </nav>

    <div class="dashboard-container">
        <aside class="sidebar">
        <nav class="nav">
                <a href="admin_dashboard.php" class="active">Dashboard</a>
                <a href="recipe-input.php">Input Recipes</a>
                <a href="recipes_collection.php">Recipes Collection</a>
                
                <a href="edu-resources-input.php">Input Education Resources</a>
                <a href="edu-resources-collection.php">Education Resources Collection</a>
                <a href="culinary-input.php">Input Culinary Trends</a>
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
                <h2>User Data</h2>
                <table class="table">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Name</th>
                            <th>Email</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php
                        if (mysqli_num_rows($userDataResult) > 0) {
                            while ($row = mysqli_fetch_assoc($userDataResult)) {
                                echo "<tr>";
                                echo "<td>" . $row['user_id'] . "</td>";
                                echo "<td>" . $row['name'] . "</td>";
                                echo "<td>" . $row['email'] . "</td>";
                                echo "<td><a href='members_info.php?delete_id=" . $row['user_id'] . "' class='btn btn-danger btn-sm'>Delete</a></td>";
                                echo "</tr>";
                            }
                        } else {
                            echo "<tr><td colspan='4'>No users found.</td></tr>";
                        }
                        ?>
                    </tbody>
                </table>

                <nav aria-label="Page navigation">
                    <ul class="pagination justify-content-center">
                        <?php if ($page > 1): ?>
                            <li class="page-item"><a class="page-link"
                                    href="members_info.php?page=<?php echo $page - 1; ?>">Previous</a></li>
                        <?php endif; ?>

                        <?php for ($i = 1; $i <= $number_of_pages; $i++): ?>
                            <li class="page-item <?php echo ($i == $page) ? 'active' : ''; ?>"><a class="page-link"
                                    href="members_info.php?page=<?php echo $i; ?>"><?php echo $i; ?></a></li>
                        <?php endfor; ?>

                        <?php if ($page < $number_of_pages): ?>
                            <li class="page-item"><a class="page-link"
                                    href="members_info.php?page=<?php echo $page + 1; ?>">Next</a></li>
                        <?php endif; ?>
                    </ul>
                </nav>
            </section>
        </main>
    </div>


</body>

</html>