<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>About Us - Food Fusion</title>
    <link rel="stylesheet" href="bootstrap/css/bootstrap.min.css">
    <link rel="stylesheet" href="css/aboutus.css?<?php echo time(); ?>">
    
</head>


<body>
    <?php
    include("navigation.php");

    ?>

    <main>
        <div class="container">
            <section class="tour-section">
                <div class="tour-content">
                    <div class="tour-text">
                        <h2>Our food fusion community Hub</h2>
                        <p>
                        Welcome to the heart of Food Fusion! Our Community Hub is where passionate food lovers, from seasoned chefs to curious home cooks, come together to share, inspire, and celebrate the joy of cooking. Dive into a world of shared recipes, lively discussions, and a supportive network that's always ready to welcome you to the table 
                        </p>


                <div class="culinary-philosophy">
                    <h2>Our Culinary Philosophy</h2>
                    <p>At Food Fusion, we believe that food is more than just sustenance; it's an experience, a
                        connection, and a celebration of culture.</p>
                    <ul>
                        <li><strong>Freshness and Quality:</strong> We prioritize using the freshest, highest-quality
                            ingredients.</li>
                        <li><strong>Innovation and Creativity:</strong> We strive to bring new and exciting flavors to
                            your table.</li>
                        <li><strong>Accessibility and Inspiration:</strong> We make cooking enjoyable and accessible to
                            everyone.</li>
                    </ul>
                </div>

                <div class="values">
                    <h2>Our Values</h2>
                    <p>Food Fusion is guided by a core set of values:</p>
                    <ul>
                        <li><strong>Community:</strong> We foster a welcoming and inclusive community for food lovers.
                        </li>
                        <li><strong>Passion:</strong> We are passionate about food and dedicated to sharing that
                            passion.</li>
                        <li><strong>Integrity:</strong> We are committed to honesty, transparency, and ethical
                            practices.</li>
                        <li><strong>Sustainability:</strong> We promote sustainable food practices and responsible
                            sourcing.</li>
                    </ul>
                </div>
                    </div>
                    <div class="tour-images">
                        <img src="image/aboutus1.jpg" alt="Berlin Image 1">
                        <img src="image/aboutus2.jpg" alt="Berlin Image 2">
                        <img src="image/aboutus3.jpg" alt="Berlin Image 3">
                    </div>
                </div>
            </section>

            <section class="about-us-content">
                <div class="team">
                    <h2>Meet the Team</h2>
                    <div class="team-members">
                        <div class="team-member">
                            <img src="image/team-member-5.jpg" alt="Team Member 1">
                            <h3>Jaemin</h3>
                            <p class="team_p">Developer</p>
                        </div>
                        
                        <div class="team-member">
                            <img src="image/team-member-3.jpg" alt="Team Member 2">
                            <h3>Mark Lee</h3>
                            <p class="team_p">Functional</p>
                        </div>
                        <div class="team-member">
                            <img src="image/team-member-4.png" alt="Team Member 2">
                            <h3>Jisung</h3>
                            <p class="team_p">Cloud Engineer</p>
                        </div>
                        <div class="team-member">
                            <img src="image/team-member-6.jpg" alt="Team Member 2">
                            <h3>Jeno</h3>
                            <p class="team_p">Developer</p>
                        </div>
                    </div>
                </div>
            </section>
        </div>
    </main>
     

    <?php
    include("footer.php");
    ?>

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
</body>

</html>