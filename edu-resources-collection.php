<?php
include("navigation.php");
include("database/db_connection.php");

// Delete Logic
if (isset($_GET['delete_id'])) {
    $deleteId = $_GET['delete_id'];
    $deleteSql = "DELETE FROM edu_resources WHERE edu_id = ?";
    $deleteStmt = $conn->prepare($deleteSql);
    $deleteStmt->bind_param("i", $deleteId);
    if ($deleteStmt->execute()) {
        echo "<script>alert('Resource deleted successfully.'); window.location.href = 'edu-resources-collection.php';</script>";
    } else {
        echo "<script>alert('Error deleting resource.');</script>";
    }
    $deleteStmt->close();
}

// Fetch data from edu_resources table
$sql = "SELECT * FROM edu_resources";
$result = $conn->query($sql);

$eduResources = [];

if ($result->num_rows > 0) {
    while ($row = $result->fetch_assoc()) {
        $eduResources[] = $row;
    }
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Educational Resources Collection</title>
    <link rel="stylesheet" href="bootstrap/css/bootstrap.min.css">
    <link rel="stylesheet" href="css/edu_resources_collection.css?<?php echo time(); ?>">
</head>

<body>
    <div class="content">
        <h2>Educational Resources Collection</h2>
        <table class="edu-resources-table">
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Name</th>
                    <th>Type</th>
                    <th>Description</th>
                    <th>Topic</th>
                    <th>Audience</th>
                    <th>Photo</th>
                    <th>Video</th>
                    <th>File</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($eduResources as $resource) : ?>
                    <tr>
                        <td><?php echo $resource['edu_id']; ?></td>
                        <td><?php echo $resource['name']; ?></td>
                        <td><?php echo $resource['type']; ?></td>
                        <td><?php echo $resource['description']; ?></td>
                        <td><?php echo $resource['topic']; ?></td>
                        <td><?php echo $resource['audience']; ?></td>
                        <td>
                            <?php if ($resource['photo']) : ?>
                                <img src="<?php echo $resource['photo']; ?>" alt="<?php echo $resource['name']; ?>" width="100">
                            <?php endif; ?>
                        </td>
                        <td>
                            <?php if ($resource['video']) : ?>
                                <a href="<?php echo $resource['video']; ?>" target="_blank">View Video</a>
                            <?php endif; ?>
                        </td>
                        <td>
                            <?php if ($resource['file']) : ?>
                                <a href="<?php echo $resource['file']; ?>" download>Download File</a>
                            <?php endif; ?>
                        </td>
                        <td>
                            <a href="update_edu_resources.php?id=<?php echo $resource['edu_id']; ?>" class="btn btn-primary btn-sm">Update</a>
                            <a href="edu-resources-collection.php?delete_id=<?php echo $resource['edu_id']; ?>" class="btn btn-danger btn-sm" onclick="return confirm('Are you sure you want to delete this resource?')">Delete</a>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>

    <?php
    include("footer.php");
    ?>

    <script src="bootstrap/js/bootstrap.bundle.min.js"></script>
</body>

</html>