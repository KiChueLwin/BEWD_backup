<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>navigation</title>
    <link rel="stylesheet" href="bootstrap/css/bootstrap.min.css">
    <link rel="stylesheet" href="css/welcome.css?<?php echo time(); ?>">


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

                    <li class="nav-item"><a class="nav-link" href="culinary_resources.php">Culinary Resources</a></li>
                    <li class="nav-item"><a class="nav-link" href="edu-resources.php">Educational Resources</a></li>
                    <li class="nav-item"><a class="nav-link" href="about-us.php">About Us</a></li>
                    <li class="nav-item"><a class="nav-link" href="contactus.php">Contact Us</a></li>
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle" href="#" id="accountDropdown" role="button"
                            aria-expanded="false"> Account
                        </a>
                        <ul class="dropdown-menu dropdown-menu-end" aria-labelledby="accountDropdown">
                            <li><a class="dropdown-item" href="login.php">Login</a></li>
                            <li><a class="dropdown-item" href="register-form.php">Register</a></li>
                        </ul>
                    </li>
                    
                </ul>
            </div>
        </div>
    </nav>
</body>


<script src="bootstrap/js/bootstrap.bundle.min.js"></script>
    <script>
        document.addEventListener('DOMContentLoaded', function () {
            const accountDropdown = document.getElementById('accountDropdown');
            const dropdownMenu = accountDropdown.nextElementSibling; // Get the <ul>

            if (accountDropdown && dropdownMenu) { // Check if elements exist
                accountDropdown.addEventListener('mouseenter', function () {
                    dropdownMenu.classList.add('show');
                    accountDropdown.setAttribute('aria-expanded', 'true');
                });

                accountDropdown.addEventListener('mouseleave', function () {
                    dropdownMenu.classList.remove('show');
                    accountDropdown.setAttribute('aria-expanded', 'false');
                });

                dropdownMenu.addEventListener('mouseenter', function () {
                    dropdownMenu.classList.add('show');
                    accountDropdown.setAttribute('aria-expanded', 'true');
                });

                dropdownMenu.addEventListener('mouseleave', function () {
                    dropdownMenu.classList.remove('show');
                    accountDropdown.setAttribute('aria-expanded', 'false');
                });
            }
        });






    </script>

</html>