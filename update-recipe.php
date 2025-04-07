<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Recipe Input</title>
    <link rel="stylesheet" href="bootstrap/css/bootstrap.min.css">
    <link rel="stylesheet" href="css/update-recipe.css?<?php echo time(); ?>">
    <style>
        body {
            background-color: white; /* Add this line to set white background */
        }
    </style>
</head>

<body>
    <?php
    include("navigation.php");
    include("database/db_connection.php");

    $recipeId = isset($_GET['recipe_id']) ? $_GET['recipe_id'] : null;
    $recipeData = null;

    if ($recipeId) {
        try {
            $stmt = $conn->prepare("SELECT * FROM recipe WHERE recipe_id = ?");
            $stmt->bind_param("i", $recipeId);

            if ($stmt->execute()) {
                $result = $stmt->get_result();
                if ($result->num_rows > 0) {
                    $recipeData = $result->fetch_assoc();
                }
            } else {
                throw new Exception("Error retrieving recipe data: " . $stmt->error);
            }
            $stmt->close();
        } catch (Exception $e) {
            echo "<script>alert('Database error: " . $e->getMessage() . "');</script>";
        }
    }

    if ($_SERVER["REQUEST_METHOD"] == "POST") {
        $name = $_POST['recipe-name'];
        $recipe_type = $_POST['recipe-type'];
        $description = $_POST['description'];
        $difficulty_level = $_POST['difficulty-level'];
        $dietary_preference = $_POST['dietary-preference'];

        if (!empty($_FILES['recipe-photo']['name'])) {
            $photo_name = $_FILES['recipe-photo']['name'];
            $tmp_name = $_FILES['recipe-photo']['tmp_name'];
            $target_file = "upload/" . $photo_name;

            if (move_uploaded_file($tmp_name, $target_file)) {
                $photo_path = $target_file;
            } else {
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

                $error_code = $_FILES['recipe-photo']['error'];
                $error_message = isset($upload_errors[$error_code]) ? $upload_errors[$error_code] : 'Unknown upload error.';

                echo "<script>alert('Error uploading new photo: " . $error_message . "');</script>";
                $photo_path = isset($recipeData['photo']) ? $recipeData['photo'] : '';
            }
        } else {
            $photo_path = isset($recipeData['photo']) ? $recipeData['photo'] : '';
        }

        if ($recipeId) {
            $stmt = $conn->prepare("UPDATE recipe SET name = ?, recipe_type = ?, description = ?, difficulty_level = ?, dietary_preference = ?, photo = ? WHERE recipe_id = ?");
            $stmt->bind_param("ssssssi", $name, $recipe_type, $description, $difficulty_level, $dietary_preference, $photo_path, $recipeId);
        } else {
            $stmt = $conn->prepare("INSERT INTO recipe (name, recipe_type, description, difficulty_level, dietary_preference, photo) VALUES (?, ?, ?, ?, ?, ?)");
            $stmt->bind_param("ssssss", $name, $recipe_type, $description, $difficulty_level, $dietary_preference, $photo_path);
        }

        if ($stmt->execute()) {
            echo "<script>alert('" . ($recipeId ? 'Recipe updated successfully.' : 'Recipe added successfully.') . "');</script>";
        } else {
            echo "<script>alert('Error: " . $stmt->error . "');</script>";
        }

        $stmt->close();
        $conn->close();
    }
    ?>

    <section class="container">
        <form class="recipe-import-form" method="POST" enctype="multipart/form-data">
            <h2><?php echo $recipeId ? 'Update Recipe' : 'Recipe Import'; ?></h2>

            <label for="recipe-name">Name:</label>
            <input type="text" id="recipe-name" name="recipe-name"
                value="<?php echo isset($recipeData['name']) ? $recipeData['name'] : ''; ?>" required>

            <label for="recipe-type">Recipe Type:</label>
            <select id="recipe-type" name="recipe-type" required>
                <option value="">Select Cuisine</option>
                <option value="Chinese" <?php if (isset($recipeData['recipe_type']) && $recipeData['recipe_type'] == 'Chinese')
                    echo 'selected'; ?>>Chinese</option>
                <option value="Japanese" <?php if (isset($recipeData['recipe_type']) && $recipeData['recipe_type'] == 'Japanese')
                    echo 'selected'; ?>>Japanese</option>
                <option value="Thai" <?php if (isset($recipeData['recipe_type']) && $recipeData['recipe_type'] == 'Thai')
                    echo 'selected'; ?>>Thai</option>
                <option value="Indian" <?php if (isset($recipeData['recipe_type']) && $recipeData['recipe_type'] == 'Indian')
                    echo 'selected'; ?>>Indian</option>
                <option value="Korean" <?php if (isset($recipeData['recipe_type']) && $recipeData['recipe_type'] == 'Korean')
                    echo 'selected'; ?>>Korean</option>
                <option value="Italian" <?php if (isset($recipeData['recipe_type']) && $recipeData['recipe_type'] == 'Italian')
                    echo 'selected'; ?>>Italian</option>
                <option value="French" <?php if (isset($recipeData['recipe_type']) && $recipeData['recipe_type'] == 'French')
                    echo 'selected'; ?>>French</option>
                <option value="Mexican" <?php if (isset($recipeData['recipe_type']) && $recipeData['recipe_type'] == 'Mexican')
                    echo 'selected'; ?>>Mexican</option>
                <option value="American" <?php if (isset($recipeData['recipe_type']) && $recipeData['recipe_type'] == 'American')
                    echo 'selected'; ?>>American</option>
                <option value="Mediterranean" <?php if (isset($recipeData['recipe_type']) && $recipeData['recipe_type'] == 'Mediterranean')
                    echo 'selected'; ?>>Mediterranean</option>
                <option value="Other" <?php if (isset($recipeData['recipe_type']) && $recipeData['recipe_type'] == 'Other')
                    echo 'selected'; ?>>Other</option>
            </select>

            <label for="description">Description:</label>
            <textarea id="description" name="description" rows="4"
                required><?php echo isset($recipeData['description']) ? $recipeData['description'] : ''; ?></textarea>

            <label for="difficulty-level">Difficulty Level:</label>
            <select id="difficulty-level" name="difficulty-level" required>
                <option value="">Select Level</option>
                <option value="easy" <?php if (isset($recipeData['difficulty_level']) && $recipeData['difficulty_level'] == 'easy')
                    echo 'selected'; ?>>Easy</option>
                <option value="medium" <?php if (isset($recipeData['difficulty_level']) && $recipeData['difficulty_level'] == 'medium')
                    echo 'selected'; ?>>Medium</option>
                <option value="hard" <?php if (isset($recipeData['difficulty_level']) && $recipeData['difficulty_level'] == 'hard')
                    echo 'selected'; ?>>Hard</option>
            </select>

            <label for="dietary-preference">Dietary Preference:</label>
            <select id="dietary-preference" name="dietary-preference" required>
                <option value="">Select Preference</option>
                <option value="Vegetarian" <?php if (isset($recipeData['dietary_preference']) && $recipeData['dietary_preference'] == 'Vegetarian')
                    echo 'selected'; ?>>Vegetarian</option>
                <option value="Non-Vegetarian" <?php if (isset($recipeData['dietary_preference']) && $recipeData['dietary_preference'] == 'Non-Vegetarian')
                    echo 'selected'; ?>>Non-Vegetarian</option>
            </select>

            <label for="recipe-photo">Photo:</label>
            <input type="file" id="recipe-photo" name="recipe-photo" <?php if (!$recipeId)
                echo 'required'; ?>>
            <?php if (isset($recipeData['photo'])): ?>
                <img src="<?php echo $recipeData['photo']; ?>" alt="Current Recipe Photo" style="max-width: 100px;">
            <?php endif; ?>

            <button type="submit"><?php echo $recipeId ? 'Update Recipe' : 'Import Recipe'; ?></button>
        </form>
    </section>

    <?php 
    include('footer.php');
    ?>

    <script src="bootstrap/js/bootstrap.bundle.min.js"></script>
</body>

</html>