<?php
include("navigation.php");
include("database/db_connection.php");

// Fetch all data from the culinary_resources table
$sql = "SELECT * FROM culinary_resources";
$result = $conn->query($sql);

$resourcesByType = array();

if ($result->num_rows > 0) {
    while ($row = $result->fetch_assoc()) {
        $type = $row["type"];
        if (!isset($resourcesByType[$type])) {
            $resourcesByType[$type] = array();
        }
        $resourcesByType[$type][] = $row;
    }
}

$conn->close();
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Culinary Resources</title>
    <link rel="stylesheet" href="bootstrap/css/bootstrap.min.css">
    <style>
        body {
            font-family: sans-serif;
            margin: 0;
            padding: 0;
            background-image: url('path/to/your/background-image.jpg');
            /* Replace with your image path */
            background-size: cover;
            /* Cover the entire viewport */
            background-position: center;
            /* Center the background image */
            background-repeat: no-repeat;
            /* Prevent the image from repeating */
            min-height: 100vh;
            /* Ensure the background covers the entire viewport height */
            /* Use flexbox to center content vertically */
            justify-content: center;
            /* Center horizontally */
            align-items: flex-start;
            /* Align items to the top (or adjust as needed) */
        }

        .content {
            padding: 100px;
            background-color: rgba(255, 255, 255, 0.9);
            /* Semi-transparent white background for content */
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);



        }

        .content h1 {
            color: #1d222c;
            text-align: center;
            align-items: center;
            font-family: 'Playfair Display', Georgia, serif;
            font-weight: 700;
        }

        .introduction-section {
            margin-bottom: 30px;
            padding: 20px;
            background-color: rgba(255, 255, 255, 0.8);
            /* Semi-transparent white background for intro */
            border-radius: 4px;
            box-shadow: 0 1px 2px rgba(0, 0, 0, 0.05);
            text-align: center;
            align-items: center;
            height: 500px;
        }

        .introduction-photo {
            align-items: center;
            max-width: 200px;
            height: auto;
            margin-right: 20px;
            border-radius: 4px;
        }

        .introduction-text p {
            margin-top: 20px;
            margin-bottom: 10px;
            color: #333;
            /* Darker text for better contrast */
        }

        .resource-section {
            margin-bottom: 30px;
            border-bottom: 1px solid #ccc;
            padding-bottom: 20px;
        }

        p {
            font-family: 'Inter', sans-serif;
        }

        .resource-section h2 {
            color: rgb(166, 26, 4);
            margin-bottom: 15px;
        }

        .resource-item {
            background-color: #f9f9f9;
            /* Slightly different background for items */
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 15px;
            margin-bottom: 10px;
            box-shadow: 0 1px 2px rgba(0, 0, 0, 0.05);
        }

        .resource-item h3 {
            margin-top: 0;
            margin-bottom: 5px;
            color: #1d222c;
        }

        .resource-item p {
            margin-bottom: 5px;
            color: #555;
        }

        .resource-item .details-label {
            font-weight: bold;
            margin-right: 5px;
        }

        .resource-item .file-link a {
            color: #007bff;
            text-decoration: none;
        }

        .resource-item .video-link a {
            color: #dc3545;
            text-decoration: none;
        }

        .no-resources {
            color: #6c757d;
            font-style: italic;
        }
    </style>
</head>

<body>
    <div class="content">
        <h1>Culinary Resources</h1>

        <div class="introduction-section">
            <img src="image/event1.jpg" alt="Culinary Delights" class="introduction-photo">
            <div class="introduction-text">
                <p>Welcome to our Culinary Resources page! Here you'll find a collection of valuable resources to
                    enhance your cooking skills and explore the world of delicious cuisine.</p>
                <p>Whether you're a beginner looking for basic recipes or an experienced cook seeking new techniques and
                    kitchen hacks, you've come to the right place. We offer a variety of content to cater to all levels
                    of culinary enthusiasts.</p>
                <p>Browse through our different categories below to discover recipe cards, cooking tutorials,
                    instructional videos, and much more!</p>
            </div>
        </div>

        <?php if (!empty($resourcesByType)): ?>
            <?php foreach ($resourcesByType as $type => $resources): ?>
                <div class="resource-section">
                    <h2><?php echo htmlspecialchars($type); ?></h2>
                    <?php if (!empty($resources)): ?>
                        <?php foreach ($resources as $resource): ?>
                            <div class="resource-item">
                                <h3><?php echo htmlspecialchars($resource['title']); ?></h3>
                                <p><span class="details-label">Description:</span>
                                    <?php echo htmlspecialchars($resource['description']); ?></p>
                                <p><span class="details-label">Cuisine Type:</span>
                                    <?php echo htmlspecialchars($resource['cuisine_type']); ?></p>
                                <p><span class="details-label">Audience:</span> <?php echo htmlspecialchars($resource['audience']); ?>
                                </p>
                                <?php if (!empty($resource['photo'])): ?>
                                    <p><span class="details-label">Photo:</span> <img
                                            src="<?php echo htmlspecialchars($resource['photo']); ?>"
                                            alt="<?php echo htmlspecialchars($resource['title']); ?>"
                                            style="max-width: 100px; max-height: 100px;"></p>
                                <?php endif; ?>
                                <?php if (!empty($resource['file'])): ?>
                                    <p class="file-link"><span class="details-label">File:</span> <a
                                            href="<?php echo htmlspecialchars($resource['file']); ?>" target="_blank">Download</a></p>
                                <?php endif; ?>
                                <?php if (!empty($resource['video'])): ?>
                                    <p class="video-link"><span class="details-label">Video:</span> <a
                                            href="<?php echo htmlspecialchars($resource['video']); ?>" target="_blank">Watch Video</a></p>
                                <?php endif; ?>
                            </div>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <p class="no-resources">No resources found in this category.</p>
                    <?php endif; ?>
                </div>
            <?php endforeach; ?>
        <?php else: ?>
            <p class="no-resources">No culinary resources have been added yet.</p>
        <?php endif; ?>
    </div>

    <?php include("footer.php"); ?>

    <script src="bootstrap/js/bootstrap.bundle.min.js"></script>
</body>

</html>