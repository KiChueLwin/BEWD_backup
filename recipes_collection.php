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

// Fetch recipes data (with pagination)
$results_per_page = 3;
$query = "SELECT * FROM recipe";
$result = mysqli_query($conn, $query);
$number_of_results = mysqli_num_rows($result);
$number_of_pages = ceil($number_of_results / $results_per_page);

if (!isset($_GET['page'])) {
    $page = 1;
} else {
    $page = $_GET['page'];
}

$start_limit = ($page - 1) * $results_per_page;
$sql = "SELECT * FROM recipe LIMIT " . $start_limit . ',' . $results_per_page;
$recipesResult = mysqli_query($conn, $sql);

// Handle delete action (if needed)
if (isset($_GET['delete_recipe_id'])) {
    $deleteRecipeId = $_GET['delete_recipe_id'];
    $deleteRecipeQuery = "DELETE FROM recipe WHERE recipe_id = ?";
    $deleteRecipeStmt = mysqli_prepare($conn, $deleteRecipeQuery);
    mysqli_stmt_bind_param($deleteRecipeStmt, "i", $deleteRecipeId);
    if (mysqli_stmt_execute($deleteRecipeStmt)) {
        header("Location: recipes_collection.php");
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
    <title>Recipes Collection</title>
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

    <?php
    include("navigation.php");

    ?>

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
                <h2>Recipes Collection</h2>
                <table class="table">
                    <thead>
                        <tr>
                            <th>Recipe ID</th>
                            <th>Recipe Name</th>

                            <th>Photo</th>
                            <th>Description</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php
                        if (mysqli_num_rows($recipesResult) > 0) {
                            while ($row = mysqli_fetch_assoc($recipesResult)) {
                                echo "<tr>";
                                echo "<td>" . $row['recipe_id'] . "</td>";
                                echo "<td>" . $row['name'] . "</td>";

                                echo "<td><img src='" . $row['photo'] . "' alt='Recipe Photo' class='recipe-photo'></td>";
                                echo "<td>" . $row['description'] . "</td>";
                                echo "<td>
                                        <a href='update-recipe.php?recipe_id=" . $row['recipe_id'] . "' class='btn btn-primary btn-sm'>Update</a>
                                        <a href='recipes_collection.php?delete_recipe_id=" . $row['recipe_id'] . "' class='btn btn-danger btn-sm'>Delete</a>
                                    </td>";
                                echo "</tr>";
                            }
                        } else {
                            echo "<tr><td colspan='5'>No recipes found.</td></tr>";
                        }
                        ?>
                    </tbody>
                </table>

                <nav aria-label="Page navigation">
                    <ul class="pagination justify-content-center">
                        <?php if ($page > 1): ?>
                            <li class="page-item"><a class="page-link"
                                    href="recipes_collection.php?page=<?php echo $page - 1; ?>">Previous</a></li>
                        <?php endif; ?>

                        <?php for ($i = 1; $i <= $number_of_pages; $i++): ?>
                            <li class="page-item <?php echo ($i == $page) ? 'active' : ''; ?>"><a class="page-link"
                                    href="recipes_collection.php?page=<?php echo $i; ?>"><?php echo $i; ?></a></li>
                        <?php endfor; ?>

                        <?php if ($page < $number_of_pages): ?>
                            <li class="page-item"><a class="page-link"
                                    href="recipes_collection.php?page=<?php echo $page + 1; ?>">Next</a></li>
                        <?php endif; ?>
                    </ul>
                </nav>
            </section>
        </main>
    </div>


    <?php
    include("footer.php");

    ?>
</body>

</html>