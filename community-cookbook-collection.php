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

// Fetch community recipes data (with pagination)
$results_per_page = 3;
$query = "SELECT * FROM community_recipes";
$result = mysqli_query($conn, $query);
$number_of_results = mysqli_num_rows($result);
$number_of_pages = ceil($number_of_results / $results_per_page);

if (!isset($_GET['page'])) {
    $page = 1;
} else {
    $page = $_GET['page'];
}

$start_limit = ($page - 1) * $results_per_page;
$sql = "SELECT * FROM community_recipes LIMIT " . $start_limit . ',' . $results_per_page;
$communityRecipesResult = mysqli_query($conn, $sql);

// Handle delete action (for community recipes)
if (isset($_GET['delete_community_recipe_id'])) {
    $deleteRecipeId = $_GET['delete_community_recipe_id'];
    $deleteRecipeQuery = "DELETE FROM community_recipes WHERE recipe_id = ?";
    $deleteRecipeStmt = mysqli_prepare($conn, $deleteRecipeQuery);
    mysqli_stmt_bind_param($deleteRecipeStmt, "i", $deleteRecipeId);
    if (mysqli_stmt_execute($deleteRecipeStmt)) {
        header("Location: community-cookbook-collection.php");
        exit;
    } else {
        echo "Error deleting recipe: " . mysqli_error($conn);
    }
    mysqli_stmt_close($deleteRecipeStmt);
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Community Cookbook Collection</title>
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

    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
    </nav>

    <div class="dashboard-container">
        <main class="main-content">
            <header class="header">
                <div class="user-profile">
                    <img src="image/user_avatar.png" alt="User Avatar">
                    <span class="admin-name"><?php echo $adminName; ?></span>
                </div>
            </header>
            <section class="content">
                <h2>Community Cookbook Collection</h2>
                <table class="table">
                    <thead>
                        <tr>
                            <th>User ID</th>
                            <th>Recipe ID</th>
                            <th>Recipe Name</th>
                            <th>Photo</th>
                            <th>Description</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php
                        if (mysqli_num_rows($communityRecipesResult) > 0) {
                            while ($row = mysqli_fetch_assoc($communityRecipesResult)) {
                                echo "<tr>";
                                echo "<td>" . $row['user_id'] . "</td>";
                                echo "<td>" . $row['recipe_id'] . "</td>";
                                echo "<td>" . $row['recipe_name'] . "</td>";
                                echo "<td><img src='" . $row['photo'] . "' alt='Recipe Photo' class='recipe-photo'></td>";
                                echo "<td>" . $row['description'] . "</td>";
                                echo "<td>
                                            <a href='community-cookbook-collection.php?delete_community_recipe_id=" . $row['recipe_id'] . "' class='btn btn-danger btn-sm'>Delete</a>
                                        </td>";
                                echo "</tr>";
                            }
                        } else {
                            echo "<tr><td colspan='5'>No community recipes found.</td></tr>";
                        }
                        ?>
                    </tbody>
                </table>

                <nav aria-label="Page navigation">
                    <ul class="pagination justify-content-center">
                        <?php if ($page > 1): ?>
                            <li class="page-item"><a class="page-link"
                                href="community-cookbook-collection.php?page=<?php echo $page - 1; ?>">Previous</a></li>
                        <?php endif; ?>

                        <?php for ($i = 1; $i <= $number_of_pages; $i++): ?>
                            <li class="page-item <?php echo ($i == $page) ? 'active' : ''; ?>"><a class="page-link"
                                href="community-cookbook-collection.php?page=<?php echo $i; ?>"><?php echo $i; ?></a></li>
                        <?php endfor; ?>

                        <?php if ($page < $number_of_pages): ?>
                            <li class="page-item"><a class="page-link"
                                href="community-cookbook-collection.php?page=<?php echo $page + 1; ?>">Next</a></li>
                        <?php endif; ?>
                    </ul>
                </nav>
            </section>
        </main>
    </div>

    <?php include("footer.php"); ?>
</body>

</html>