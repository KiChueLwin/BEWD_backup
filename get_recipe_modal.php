<?php
session_start();
include("database/db_connection.php");

$recipe_id = $_GET['recipe_id'];

// Fetch recipe details
$sql_recipe = "SELECT * FROM community_recipes WHERE recipe_id = ?";
$stmt_recipe = $conn->prepare($sql_recipe);
$stmt_recipe->bind_param("i", $recipe_id);
$stmt_recipe->execute();
$recipe = $stmt_recipe->get_result()->fetch_assoc();
$stmt_recipe->close();

// Fetch average rating
$sql_rating = "SELECT AVG(rating) as avg_rating FROM ratings WHERE recipe_id = ?";
$stmt_rating = $conn->prepare($sql_rating);
$stmt_rating->bind_param("i", $recipe_id);
$stmt_rating->execute();
$result_rating = $stmt_rating->get_result()->fetch_assoc();
$recipe['avg_rating'] = round($result_rating['avg_rating'], 1);
$stmt_rating->close();

// Fetch comments
$sql_comments = "SELECT comments.*, users.name FROM comments JOIN users ON comments.user_id = users.user_id WHERE recipe_id = ?";
$stmt_comments = $conn->prepare($sql_comments);
$stmt_comments->bind_param("i", $recipe_id);
$stmt_comments->execute();
$result_comments = $stmt_comments->get_result()->fetch_all(MYSQLI_ASSOC);
$recipe['comments'] = $result_comments;
$stmt_comments->close();

// Generate modal content
?>

<div class="modal-dialog modal-dialog-scrollable modal-lg">
    <div class="modal-content">
        <div class="modal-header">
            <h5 class="modal-title" id="recipeModalLabel<?php echo $recipe['recipe_id']; ?>"><?php echo htmlspecialchars($recipe['recipe_name']); ?></h5>
            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
        </div>
        <div class="modal-body">
            <?php if (!empty($recipe['photo'])): ?><img src="<?php echo $recipe['photo']; ?>" class="img-fluid mb-3" alt="<?php echo htmlspecialchars($recipe['recipe_name']); ?>"><?php endif; ?>
            <h6>Description:</h6><p><?php echo htmlspecialchars($recipe['description']); ?></p>
            <h6>Ingredients:</h6><p><?php echo nl2br(htmlspecialchars($recipe['ingredients'])); ?></p>
            <h6>Instructions:</h6><p><?php echo nl2br(htmlspecialchars($recipe['instructions'])); ?></p>
            <p><strong>Cuisine:</strong> <?php echo htmlspecialchars($recipe['cuisine_type']); ?></p>
            <p><strong>Dietary Preference:</strong> <?php echo htmlspecialchars($recipe['dietary_preference']); ?></p>
            <p class="text-muted">Submitted on: <?php echo date("F j, Y", strtotime($recipe['submission_date'])); ?></p>
            <h6>Ratings:</h6>
            <p>Average Rating: <?php echo $recipe['avg_rating'] ? htmlspecialchars($recipe['avg_rating']) : 'No ratings yet'; ?></p>
            <?php if (isset($_SESSION['user_id'])): ?>
                <form action="rate_recipe.php" method="post">
                    <input type="hidden" name="recipe_id" value="<?php echo $recipe['recipe_id']; ?>">
                    <select name="rating">
                        <?php for ($i = 1; $i <= 5; $i++): ?><option value="<?php echo $i; ?>"><?php echo $i; ?></option><?php endfor; ?>
                    </select>
                    <button type="submit" class="btn btn-sm btn-primary">Rate</button>
                </form>
            <?php else: ?>
                <p>Please log in to rate this recipe.</p>
            <?php endif; ?>
            <h6>Comments:</h6>
            <?php if(!empty($recipe['comments'])): ?>
                <?php foreach ($recipe['comments'] as $comment): ?>
                    <p><?php echo htmlspecialchars($comment['comment_text']); ?> - <?php echo htmlspecialchars($comment['username']); ?></p>
                <?php endforeach; ?>
            <?php endif; ?>
            <?php if (isset($_SESSION['user_id'])): ?>
                <form action="add_comment.php" method="post">
                    <input type="hidden" name="recipe_id" value="<?php echo $recipe['recipe_id']; ?>">
                    <textarea name="comment_text" class="form-control" placeholder="Write a comment..."></textarea>
                    <button type="submit" class="btn btn-sm btn-success">Comment</button>
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
<?php $conn->close(); ?>