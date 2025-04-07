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

// Fetch contact messages data
$sql = "SELECT * FROM contact";
$contactResult = mysqli_query($conn, $sql);

// Handle delete action (for contact messages)
if (isset($_GET['delete_contact_id'])) {
    $deleteContactId = $_GET['delete_contact_id'];
    $deleteContactQuery = "DELETE FROM contact WHERE contact_id = ?";
    $deleteContactStmt = mysqli_prepare($conn, $deleteContactQuery);
    mysqli_stmt_bind_param($deleteContactStmt, "i", $deleteContactId);
    if (mysqli_stmt_execute($deleteContactStmt)) {
        header("Location: contact-messages.php");
        exit;
    } else {
        echo "Error deleting message: " . mysqli_error($conn);
    }
    mysqli_stmt_close($deleteContactStmt);
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Contact Messages</title>
    <link rel="stylesheet" href="bootstrap/css/bootstrap.min.css">
    <link rel="stylesheet" href="css/admin.css?<?php echo time(); ?>">
</head>

<body>

    <?php include("navigation.php"); ?>

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
                <h2>Contact Messages</h2>
                <table class="table">
                    <thead>
                        <tr>
                            <th>Contact ID</th>
                            <th>Name</th>
                            <th>Email</th>
                            <th>Message</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php
                        if (mysqli_num_rows($contactResult) > 0) {
                            while ($row = mysqli_fetch_assoc($contactResult)) {
                                echo "<tr>";
                                echo "<td>" . $row['contact_id'] . "</td>";
                                echo "<td>" . $row['name'] . "</td>";
                                echo "<td>" . $row['email'] . "</td>";
                                echo "<td>" . $row['message'] . "</td>";
                                echo "<td>
                                        <a href='contact-messages.php?delete_contact_id=" . $row['contact_id'] . "' class='btn btn-danger btn-sm'>Delete</a>
                                    </td>";
                                echo "</tr>";
                            }
                        } else {
                            echo "<tr><td colspan='5'>No contact messages found.</td></tr>";
                        }
                        ?>
                    </tbody>
                </table>
            </section>
        </main>
    </div>

    <?php include("footer.php"); ?>
</body>

</html>