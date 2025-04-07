<?php
// edu-resources.php

include 'database/db_connection.php';
include("navigation.php");

// Fetch all data from edu_resources table
$query = "SELECT * FROM edu_resources";
$result = $conn->query($query);

// Store all rows in an array
$resources = [];
while ($row = $result->fetch_assoc()) {
    $resources[] = $row;
}

?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Educational Resources</title>
    <link rel="stylesheet" href="bootstrap/css/bootstrap.min.css">
    <link rel="stylesheet" href="css/edu_resources.css?<?php echo time(); ?>">
</head>

<body>
    <section class="intro-section">
        <div class="intro-overlay">
            <h1>Explore Educational Resources</h1>
            <p>Discover a variety of infographics, videos, and downloadable resources to enhance your learning experience.</p>
        </div>
    </section>

    <div class="resource-section">
        <h2>Downloadable Resources</h2>
        <div class="resource-grid">
            <?php
            foreach ($resources as $row) {
                if ($row['type'] == 'Downloadable Resource') {
                    echo "<div class='resource-item'>";
                    if (!empty($row['photo'])) {
                        echo "<img src='" . $row['photo'] . "' alt='Resource Photo'>";
                    }
                    echo "<h3>" . $row['name'] . "</h3>";
                    echo "<p>" . $row['description'] . "</p>";
                    if (!empty($row['file'])) {
                        echo "<a href='" . $row['file'] . "' download>Download File</a>";
                    }
                    echo "</div>";
                }
            }
            ?>
        </div>

        <h2>Infographic</h2>
        <div class="resource-grid">
            <?php
            foreach ($resources as $row) {
                if ($row['type'] == 'Infographic') {
                    echo "<div class='resource-item'>";
                    if (!empty($row['photo'])) {
                        echo "<img src='" . $row['photo'] . "' alt='Resource Photo'>";
                    }
                    echo "<h3>" . $row['name'] . "</h3>";
                    echo "<p>" . $row['description'] . "</p>";
                    echo "</div>";
                }
            }
            ?>
        </div>

        <h2>Videos</h2>
        <div class="resource-grid">
            <?php
            foreach ($resources as $row) {
                if ($row['type'] == 'Video') {
                    echo "<div class='resource-item'>";
                    echo "<h3>" . $row['name'] . "</h3>";
                    echo "<p>" . $row['description'] . "</p>";
                    if (!empty($row['video'])) {
                        // Convert YouTube URL to embed format
                        $youtubeUrl = $row['video'];
                        $videoId = parse_url($youtubeUrl, PHP_URL_QUERY);
                        parse_str($videoId, $params);
                        $embedUrl = "https://www.youtube.com/embed/" . $params['v'];

                        echo "<div class='video-container'><iframe src='" . $embedUrl . "' frameborder='0' allowfullscreen></iframe></div>";
                    }
                    echo "</div>";
                }
            }
            ?>
        </div>
    </div>

    <script src="bootstrap/js/bootstrap.bundle.min.js"></script>

<?php
include("footer.php");

?>

</body>

</html>