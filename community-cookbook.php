<?php
session_start();
include("database/db_connection.php");

$submission_message = "";

// Handle Recipe Submission
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['recipe_name'])) {
    //var_dump($_POST);

    $recipe_name = trim($_POST['recipe_name'] ?? '');
    $description = trim($_POST['description'] ?? '');
    $ingredients = trim($_POST['ingredients'] ?? '');
    $instructions = trim($_POST['instructions'] ?? '');
    $cuisine_type = trim($_POST['cuisine_type'] ?? '');
    $dietary_preference = trim($_POST['dietary_preference'] ?? '');

    if (empty($recipe_name)) {
        $submission_message = '<div class="alert alert-danger" role="alert">Recipe name is required.</div>';
    } elseif (empty($description)) {
        $submission_message = '<div class="alert alert-danger" role="alert">Short description is required.</div>';
    } elseif (empty($ingredients)) {
        $submission_message = '<div class="alert alert-danger" role="alert">Ingredients are required.</div>';
    } elseif (empty($instructions)) {
        $submission_message = '<div class="alert alert-danger" role="alert">Instructions are required.</div>';
    } elseif (empty($cuisine_type)) {
        $submission_message = '<div class="alert alert-danger" role="alert">Please select a cuisine type.</div>';
    } elseif (empty($dietary_preference)) {
        $submission_message = '<div class="alert alert-danger" role="alert">Please select a dietary preference.</div>';
    }

    $photo_path = "";
    if (empty($submission_message) && isset($_FILES['recipe_photo']) && $_FILES['recipe_photo']['error'] == UPLOAD_ERR_OK) {
        $upload_dir = "community_uploads/";
        if (!is_dir($upload_dir)) {
            mkdir($upload_dir, 0755, true);
        }
        $filename = basename($_FILES['recipe_photo']['name']);
        $target_file = $upload_dir . uniqid() . "_" . $filename;
        $imageFileType = strtolower(pathinfo($target_file, PATHINFO_EXTENSION));
        $allowedTypes = array("jpg", "jpeg", "png", "gif");

        if (!in_array($imageFileType, $allowedTypes)) {
            $submission_message = '<div class="alert alert-danger" role="alert">Sorry, only JPG, JPEG, PNG, and GIF files are allowed for the photo.</div>';
        } else {
            if (move_uploaded_file($_FILES['recipe_photo']['tmp_name'], $target_file)) {
                $photo_path = $target_file;
            } else {
                $submission_message = '<div class="alert alert-danger" role="alert">Error uploading photo.</div>';
            }
        }
    }

    if (empty($submission_message)) {
        if (isset($_SESSION['user_id']) && !empty($_SESSION['user_id'])) {
            $user_id = $_SESSION['user_id'];
            $stmt = $conn->prepare("INSERT INTO community_recipes (user_id, recipe_name, description, ingredients, instructions, cuisine_type, dietary_preference, photo, submission_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())");
            $stmt->bind_param("isssssss", $user_id, $recipe_name, $description, $ingredients, $instructions, $cuisine_type, $dietary_preference, $photo_path);

            if ($stmt->execute()) {
                $submission_message = '<div class="alert alert-success" role="alert">Recipe submitted successfully!</div>';
                $_POST = array();
            } else {
                $submission_message = '<div class="alert alert-danger" role="alert">Error submitting recipe: ' . $stmt->error . '</div>';
            }
            $stmt->close();
        } else {
            $submission_message = '<div class="alert alert-warning" role="alert">Please log in to submit a recipe.</div>';
        }
    }
}

// Handle Comment Submission (No Validation)
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['comment_text']) && isset($_POST['recipe_id'])) {
    if (isset($_SESSION['user_id'])) {
        $user_id = $_SESSION['user_id'];
        $comment_text = trim($_POST['comment_text']);
        $recipe_id = $_POST['recipe_id'];

        $stmt_insert = $conn->prepare("INSERT INTO comments (user_id, comment_text, recipe_id, comment_date) VALUES (?, ?, ?, NOW())");
        $stmt_insert->bind_param("isi", $user_id, $comment_text, $recipe_id);
        if ($stmt_insert->execute()) {
            // Comment added successfully.
        } else {
            $submission_message = '<div class="alert alert-danger" role="alert">Error posting comment: ' . $stmt_insert->error . '</div>';
        }
        $stmt_insert->close();
    } else {
        $submission_message = '<div class="alert alert-warning" role="alert">Please log in to post a comment.</div>';
    }
}

// Function to fetch comments for a specific recipe
function getRecipeComments($conn, $recipe_id) {
    $comments = [];
    $sql_comments = "SELECT comments.*, users.name AS user_name FROM comments JOIN users ON comments.user_id = users.user_id WHERE comments.recipe_id = ? ORDER BY comment_date DESC";
    $stmt_comments = $conn->prepare($sql_comments);
    $stmt_comments->bind_param("i", $recipe_id);
    if ($stmt_comments->execute()) {
        $result_comments = $stmt_comments->get_result();
        if ($result_comments->num_rows > 0) {
            while ($row = $result_comments->fetch_assoc()) {
                $comments[] = $row;
            }
        }
    }
    $stmt_comments->close();
    return $comments;
}

// Pagination Logic
$results_per_page = 4;
$current_page = isset($_GET['page']) ? (int) $_GET['page'] : 1;
$offset = ($current_page - 1) * $results_per_page;

$sql_count = "SELECT COUNT(*) AS total FROM community_recipes";
$result_count = $conn->query($sql_count);
$row_count = $result_count->fetch_assoc();
$total_recipes = $row_count['total'];
$total_pages = ceil($total_recipes / $results_per_page);

$sql_recipes = "SELECT community_recipes.*, users.name AS user_name FROM community_recipes JOIN users ON community_recipes.user_id = users.user_id ORDER BY submission_date DESC LIMIT ?, ?";
$stmt_recipes = $conn->prepare($sql_recipes);
$stmt_recipes->bind_param("ii", $offset, $results_per_page);

$recipes = [];
if ($stmt_recipes->execute()) {
    $result_recipes = $stmt_recipes->get_result();
    if ($result_recipes->num_rows > 0) {
        while ($row = $result_recipes->fetch_assoc()) {
            $recipes[] = $row;
        }
    }
} else {
    $submission_message = '<div class="alert alert-danger" role="alert">Error fetching recipes: ' . $stmt_recipes->error . '</div>';
}
$stmt_recipes->close();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Community Cookbook</title>
    <link rel="stylesheet" href="bootstrap/css/bootstrap.min.css">
    <link rel="stylesheet" href="css/community-cookbook.css?<?php echo time(); ?>">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="#"><img src="image/logo3.png" alt="Logo" height="40"></a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ms-auto">
                    <li class="nav-item"><a class="nav-link active" href="home1.php">Home</a></li>
                    <li class="nav-item"><a class="nav-link" href="recipes.php">Recipes Collection</a></li>
                    <li class="nav-item"><a class="nav-link" href="community-cookbook.php">Community Cookbook</a></li>
                    <li class="nav-item"><a class="nav-link" href="edu-resources.php">Educational Resources</a></li>
                    <li class="nav-item"><a class="nav-link" href="about-us.php">About Us</a></li>
                    <li class="nav-item"><a class="nav-link" href="contactus.php">Contact Us</a></li>
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle" href="#" id="accountDropdown" role="button" aria-expanded="false"> Account </a>
                        <ul class="dropdown-menu dropdown-menu-end" aria-labelledby="accountDropdown">
                            <li><a class="dropdown-item" href="community-login.php">Login</a></li>
                            <li><a class="dropdown-item" href="register-form.php">Register</a></li>
                        </ul>
                    </li>
                </ul>
            </div>
        </div>
    </nav>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const accountDropdown = document.getElementById('accountDropdown');
            const dropdownMenu = accountDropdown.nextElementSibling;
            if (accountDropdown && dropdownMenu) {
                accountDropdown.addEventListener('mouseenter', function() {
                    dropdownMenu.classList.add('show');
                    accountDropdown.setAttribute('aria-expanded', 'true');
                });
                accountDropdown.addEventListener('mouseleave', function() {
                    dropdownMenu.classList.remove('show');
                    accountDropdown.setAttribute('aria-expanded', 'false');
                });
                dropdownMenu.addEventListener('mouseenter', function() {
                    dropdownMenu.classList.add('show');
                    accountDropdown.setAttribute('aria-expanded', 'true');
                });
                dropdownMenu.addEventListener('mouseleave', function() {
                    dropdownMenu.classList.remove('show');
                    accountDropdown.setAttribute('aria-expanded', 'false');
                });
            }
        });
    </script>
    <div class="container community-cookbook-page">
        
        <?php if (!empty($submission_message)) echo $submission_message; ?>
        <div class="row">
            <div class="col-md-6">
                <h2>Submit Your Recipe</h2>
                <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post" enctype="multipart/form-data" class="community-recipe-form">
                    <div class="form-group">
                        <label for="recipe_name">Recipe Name:</label>
                        <input type="text" class="form-control" id="recipe_name" name="recipe_name" required>
                    </div>
                    <div class="form-group">
                        <label for="description">Short Description:</label>
                        <textarea class="form-control" id="description" name="description" rows="3" required></textarea>
                    </div>
                    <div class="form-group">
                        <label for="ingredients">Ingredients:</label>
                        <textarea class="form-control" id="ingredients" name="ingredients" rows="5" required placeholder="List ingredients with quantities."></textarea>
                    </div>
                    <div class="form-group">
                        <label for="instructions">Instructions:</label>
                        <textarea class="form-control" id="instructions" name="instructions" rows="8" required></textarea>
                    </div>
                    <div class="form-group">
                        <label for="cuisine_type">Cuisine Type:</label>
                        <select class="form-control" id="cuisine_type" name="cuisine_type">
                            <option value="">Select Cuisine</option>
                            <option value="Chinese">Chinese</option>
                            <option value="Japanese">Japanese</option>
                            <option value="Thai">Thai</option>
                            <option value="Indian">Indian</option>
                            <option value="Italian">Italian</option>
                            <option value="Mexican">Mexican</option>
                            <option value="American">American</option>
                            <option value="Other">Other</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label for="dietary_preference">Dietary Preference:</label>
                        <select class="form-control" id="dietary_preference" name="dietary_preference">
                            <option value="">Select Preference</option>
                            <option value="Vegetarian">Vegetarian</option>
                            <option value="Vegan">Vegan</option>
                            <option value="Gluten-Free">Gluten-Free</option>
                            <option value="Other">Other</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label for="recipe_photo">Recipe Photo:</label>
                        <input type="file" class="form-control-file" id="recipe_photo" name="recipe_photo">
                        <small class="form-text text-muted">Optional: Add a photo of your dish.</small>
                    </div>
                    <button type="submit" class="btn btn-primary">Submit Recipe</button>
                </form>
            </div>
            <div class="col-md-6">
                <h2>Community Recipes</h2>
                <div class="row">
                    <?php if (!empty($recipes)): ?>
                        <?php foreach ($recipes as $recipe): ?>
                            <div class="col-md-6 mb-4">
                                <div class="card">
                                    <?php if (!empty($recipe['photo'])): ?>
                                        <img src="<?php echo $recipe['photo']; ?>" class="card-img-top" alt="<?php echo htmlspecialchars($recipe['recipe_name']); ?>">
                                    <?php else: ?>
                                        <img src="images/default-recipe.jpg" class="card-img-top" alt="Default Recipe Image">
                                    <?php endif; ?>
                                    <div class="card-body">
                                        <h5 class="card-title"><?php echo htmlspecialchars($recipe['recipe_name']); ?></h5>
                                        <p class="card-text"><?php echo htmlspecialchars(substr(strip_tags($recipe['description']), 0, 100)); ?>...</p>
                                        <a href="#" class="btn btn-info btn-sm" data-bs-toggle="modal" data-bs-target="#recipeModal<?php echo $recipe['recipe_id']; ?>">View Recipe</a>
                                    </div>
                                </div>
                            </div>
                            <div class="modal fade" id="recipeModal<?php echo $recipe['recipe_id']; ?>" tabindex="-1" aria-labelledby="recipeModalLabel<?php echo $recipe['recipe_id']; ?>" aria-hidden="true">
                                <div class="modal-dialog modal-dialog-scrollable modal-lg">
                                    <div class="modal-content">
                                        <div class="modal-header">
                                            <h5 class="modal-title" id="recipeModalLabel<?php echo $recipe['recipe_id']; ?>"><?php echo htmlspecialchars($recipe['recipe_name']); ?></h5>
                                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                                        </div>
                                        <div class="modal-body">
                                            <?php if (!empty($recipe['photo'])): ?>
                                                <img src="<?php echo $recipe['photo']; ?>" class="img-fluid mb-3" alt="<?php echo htmlspecialchars($recipe['recipe_name']); ?>">
                                            <?php endif; ?>
                                            <h6>Description:</h6>
                                            <p><?php echo htmlspecialchars($recipe['description']); ?></p>
                                            <h6>Ingredients:</h6>
                                            <p><?php echo nl2br(htmlspecialchars($recipe['ingredients'])); ?></p>
                                            <h6>Instructions:</h6>
                                            <p><?php echo nl2br(htmlspecialchars($recipe['instructions'])); ?></p>
                                            <p><strong>Cuisine:</strong> <?php echo htmlspecialchars($recipe['cuisine_type']); ?></p>
                                            <p><strong>Dietary Preference:</strong> <?php echo htmlspecialchars($recipe['dietary_preference']); ?></p>
                                            <p><strong>Uploaded by:</strong> <?php echo htmlspecialchars($recipe['user_name']); ?></p>
                                            <p class="text-muted">Submitted on: <?php echo date("F j, Y", strtotime($recipe['submission_date'])); ?></p>
                                            <h6>Comments:</h6>
                                            <?php
                                            $recipe_comments = getRecipeComments($conn, $recipe['recipe_id']);
                                            if (!empty($recipe_comments)):
                                                foreach ($recipe_comments as $comment):
                                            ?>
                                                    <div class="comment">
                                                        <p><strong><?php echo htmlspecialchars($comment['user_name']); ?>:</strong> <?php echo htmlspecialchars($comment['comment_text']); ?></p>
                                                        <small class="text-muted"><?php echo date("F j, Y, g:i a", strtotime($comment['comment_date'])); ?></small>
                                                    </div>
                                            <?php
                                                endforeach;
                                            else:
                                            ?>
                                                <p>No comments yet.</p>
                                            <?php endif; ?>
                                            <?php if (isset($_SESSION['user_id'])): ?>
                                                <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post" class="comment-form">
                                                    <input type="hidden" name="recipe_id" value="<?php echo $recipe['recipe_id']; ?>">
                                                    <div class="form-group">
                                                        <textarea class="form-control" name="comment_text" placeholder="Add a comment..." required></textarea>
                                                    </div>
                                                    <button type="submit" class="btn btn-primary">Post Comment</button>
                                                </form>
                                            <?php else: ?>
                                                <p>Please log in to leave a comment.</p>
                                            <?php endif; ?>
                                        </div>
                                        <div class="modal-footer">
                                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <p>No community recipes have been submitted yet. Be the first to share!</p>
                    <?php endif; ?>
                </div>
                <?php if ($total_pages > 1): ?>
                    <nav aria-label="Recipe Pagination">
                        <ul class="pagination justify-content-center">
                            <?php if ($current_page > 1): ?>
                                <li class="page-item">
                                    <a class="page-link" href="?page=<?php echo $current_page - 1; ?>" aria-label="Previous">
                                        <span aria-hidden="true">&laquo;</span>
                                    </a>
                                </li>
                            <?php endif; ?>
                            <?php
                            $start_page = max(1, $current_page - 2);
                            $end_page = min($total_pages, $current_page + 2);
                            for ($i = $start_page; $i <= $end_page; $i++): ?>
                                <li class="page-item <?php echo ($i == $current_page) ? 'active' : ''; ?>">
                                    <a class="page-link" href="?page=<?php echo $i; ?>"><?php echo $i; ?></a>
                                </li>
                            <?php endfor; ?>
                            <?php if ($current_page < $total_pages): ?>
                                <li class="page-item">
                                    <a class="page-link" href="?page=<?php echo $current_page + 1; ?>" aria-label="Next">
                                        <span aria-hidden="true">&raquo;</span>
                                    </a>
                                </li>
                            <?php endif; ?>
                        </ul>
                    </nav>
                <?php endif; ?>
            </div>
        </div>
    </div>
    <script src="bootstrap/js/bootstrap.bundle.min.js"></script>
</body>
</html>
<?php $conn->close(); ?>