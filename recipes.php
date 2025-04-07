<?php
// recipes.php

include 'database/db_connection.php';

// Fetch recipes for Recipe Collection
$stmt = $conn->prepare("SELECT * FROM recipe");
$stmt->execute();
$result = $stmt->get_result();
$stmt->close();

// Get filters from GET request
$cuisine = $_GET['cuisine'] ?? '';
$dietary = $_GET['dietary'] ?? '';
$difficulty_level = $_GET['difficulty_level'] ?? '';

// SQL query with filters
$query = "SELECT * FROM recipe WHERE 1=1";

if (!empty($cuisine)) {
    $query .= " AND recipe_type = '$cuisine'";
}
if (!empty($dietary)) {
    $query .= " AND dietary_preference = '$dietary'";
}
if (!empty($difficulty_level)) {
    $query .= " AND difficulty_level = '$difficulty_level'";
}
$result1 = $conn->query($query);
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Recipes Collection</title>
    <link rel="stylesheet" href="bootstrap/css/bootstrap.min.css">
    <link rel="stylesheet" href="css/recipes.css?<?php echo time(); ?>">
</head>
<?php
include("navigation.php");
?>

<body>
    <section class="recipe-intro">
        <div class="container">
            <h1>Welcome to Our Recipe Collection</h1>
            <p>Explore a world of flavors with our diverse collection of recipes. From quick and easy meals to gourmet
                delights, we have something for everyone. Use the filters below to find your perfect dish.</p>
            <img src="image/chef.jpg" alt="Chef preparing food" class="intro-image">
        </div>
    </section>

    <div class="recipe-header">
        <h1>Filter Recipes</h1>
    </div>
    <form method="GET" action="">
        <select name="cuisine">
            <option value="">Select Cuisine</option>
            <option value="">All</option>
            <option value="Italian" <?= $cuisine == "Italian" ? "selected" : "" ?>>Italian</option>
            <option value="Chinese" <?= $cuisine == "Chinese" ? "selected" : "" ?>>Chinese</option>
            <option value="Indian" <?= $cuisine == "Indian" ? "selected" : "" ?>>Indian</option>
            <option value="Mexican" <?= $cuisine == "Mexican" ? "selected" : "" ?>>Mexican</option>
            <option value="American" <?= $cuisine == "American" ? "selected" : "" ?>>American</option>
            <option value="Japanese" <?= $cuisine == "Japanese" ? "selected" : "" ?>>Japanese</option>
            <option value="French" <?= $cuisine == "French" ? "selected" : "" ?>>French</option>
            <option value="Mediterranean" <?= $cuisine == "Mediterranean" ? "selected" : "" ?>>Mediterranean</option>
            <option value="Thai" <?= $cuisine == "Thai" ? "selected" : "" ?>>Thai</option>
            <option value="Greek" <?= $cuisine == "Greek" ? "selected" : "" ?>>Greek</option>
            <option value="Spanish" <?= $cuisine == "Spanish" ? "selected" : "" ?>>Spanish</option>
            <option value="Korean" <?= $cuisine == "Korean" ? "selected" : "" ?>>Korean</option>
            <option value="Turkish" <?= $cuisine == "Turkish" ? "selected" : "" ?>>Turkish</option>
            <option value="Vietnamese" <?= $cuisine == "Vietnamese" ? "selected" : "" ?>>Vietnamese</option>
            <option value="Caribbean" <?= $cuisine == "Caribbean" ? "selected" : "" ?>>Caribbean</option>
            <option value="African" <?= $cuisine == "African" ? "selected" : "" ?>>African</option>
        </select>

        <select name="dietary">
            <option value="">Select Dietary Preference</option>
            <option value="">All</option>
            <option value="Vegetarian" <?= $dietary == "Vegetarian" ? "selected" : "" ?>>Vegetarian</option>
            <option value="Non-Vegetarian" <?= $dietary == "Non-Vegetarian" ? "selected" : "" ?>>Non-Vegetarian</option>
            <option value="Vegan" <?= $dietary == "Vegan" ? "selected" : "" ?>>Vegan</option>
        </select>

        <select name="difficulty_level">
            <option value="">Select Difficulty</option>
            <option value="">All</option>
            <option value="easy" <?= $difficulty_level == "easy" ? "selected" : "" ?>>Easy</option>
            <option value="medium" <?= $difficulty_level == "medium" ? "selected" : "" ?>>Medium</option>
            <option value="hard" <?= $difficulty_level == "hard" ? "selected" : "" ?>>Hard</option>
        </select>

        <button type="submit">Filter</button>
    </form>

    <div class="container">
        <?php
        if ($result1) {
            while ($recipe = $result1->fetch_assoc()) {
                $recp_id = $recipe["recipe_id"];
                echo "<div class='card' data-recipe-id='" . $recp_id . "'>
                <img src='" . $recipe['photo'] . "' alt='Recipe Image'>
                <h3>" . $recipe['name'] . "</h3>
                <p><strong>Cuisine Type:</strong> " . $recipe['recipe_type'] . "</p>
                <p><strong>Dietary Preferences:</strong> " . $recipe['dietary_preference'] . "</p>
                <p><strong>Cooking Difficulty:</strong> " . $recipe['difficulty_level'] . "</p>
                <a href=\"#\" class=\"custom-view-recipe-btn\" data-bs-toggle=\"modal\" data-bs-target=\"#recipeModal" . $recp_id . "\">View Recipe</a>
            </div>";

                echo "
                <div class=\"modal fade\" id=\"recipeModal" . $recp_id . "\" tabindex=\"-1\" aria-labelledby=\"recipeModalLabel" . $recp_id . "\" aria-hidden=\"true\">
                    <div class=\"modal-dialog modal-dialog-scrollable modal-lg\">
                        <div class=\"modal-content\">
                            <div class=\"modal-header\">
                                <h5 class=\"modal-title\" id=\"recipeModalLabel" . $recp_id . "\">" . htmlspecialchars($recipe['name']) . "</h5>
                                <button type=\"button\" class=\"btn-close\" data-bs-dismiss=\"modal\" aria-label=\"Close\"></button>
                            </div>
                            <div class=\"modal-body\">
                                <img src=\"" . $recipe['photo'] . "\" class=\"img-fluid mb-3\" alt=\"" . htmlspecialchars($recipe['name']) . "\">
                                <h6>Description:</h6>
                                <p>" . htmlspecialchars($recipe['description']) . "</p>
                                <h6>Ingredients:</h6>
                                
                                <p><strong>Cuisine:</strong> " . htmlspecialchars($recipe['recipe_type']) . "</p>
                                <p><strong>Dietary Preference:</strong> " . htmlspecialchars($recipe['dietary_preference']) . "</p>
                                <p><strong>Difficulty:</strong> " . htmlspecialchars($recipe['difficulty_level']) . "</p>
                            </div>
                            <div class=\"modal-footer\">
                                <button type=\"button\" class=\"btn btn-secondary\" data-bs-dismiss=\"modal\">Close</button>
                            </div>
                        </div>
                    </div>
                </div>";
            }
        }
        ?>
    </div>

    <script src="bootstrap/js/bootstrap.bundle.min.js"></script>

    <?php
    include("footer.php");
    ?>
</body>
</html>
<?php
$conn->close();
?>