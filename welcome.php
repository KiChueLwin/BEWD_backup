<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Food Fusion</title>
    <link rel="stylesheet" href="bootstrap/css/bootstrap.min.css">
    <link rel="stylesheet" href="css/home.css?<?php echo time(); ?>">
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
                    <li class="nav-item"><a class="nav-link" href="educational.php">Educational Resources</a></li>
                    
                    <li class="nav-item"><a class="nav-link" href="about-us.php">About Us</a></li>
                    <li class="nav-item"><a class="nav-link" href="contactus.php">Contact Us</a></li>
                    <li class="nav-item">
                        <a class="nav-link btn btn-dashboard" href="home1.php" id="dashboard-btn">Logout</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="#" id="account-btn"></a>
                    </li>
                </ul>
            </div>
        </div>
    </nav>

    <header class="home-contact text-white text-center">
        <div class="container">
            <h1>Discover the Best <span class="text-accent">Recipes & Culinary Tips!</span></h1>
            <p>Explore our exclusive recipe collection!</p>
            <button class="join-us-button" data-bs-toggle="modal" data-bs-target="#registerModal" id="join-us-btn">Your Dashboard</button>
            <div class="stats-container">
                <div class="stat-item">
                    <p class="stat-number">1000+</p>
                    <p class="stat-label">Recipes</p>
                </div>
                <div class="stat-item">
                    <p class="stat-number">25k+</p>
                    <p class="stat-label">Community Members</p>
                </div>
                <div class="stat-item">
                    <p class="stat-number">50+</p>
                    <p class="stat-label">Cuisines</p>
                </div>
                <div class="stat-item">
                    <p class="stat-number">100+</p>
                    <p class="stat-label">Expert Chefs</p>
                </div>
            </div>
            <p class="admin-link">Sign in as <a href="admin-login.php">Admin!</a></p>
            <div class="scroll-indicator">
                <a href="#featured-content">
                    <svg width="32" height="32" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                        <path d="M6 9L12 15L18 9" stroke="white" stroke-width="2" stroke-linecap="round"
                            stroke-linejoin="round" />
                    </svg>
                </a>
            </div>
        </div>
    </header>

    <div class="modal fade" id="registerModal" tabindex="-1" aria-labelledby="registerModalLabel" aria-hidden="true">
        <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="registerModalLabel">Join Food Fusion</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <form id="registrationForm">
                        <div class="mb-3">
                            <label for="username" class="form-label">User Name</label>
                            <input type="text" class="form-control" id="username" name="username" required>
                        </div>
                        <div class="mb-3">
                            <label for="email" class="form-label">Email</label>
                            <input type="email" class="form-control" id="email" name="email" required>
                        </div>
                        <div class="mb-3">
                            <label for="password" class="form-label">Password</label>
                            <input type="password" class="form-control" id="password" name="password" required>
                        </div>
                        <button type="submit" class="btn btn-primary">Register</button>
                    </form>
                </div>
            </div>
        </div>
    </div>

    <section class="mission-section" id="mission-section">
        <div class="container">
            <div class="row align-items-center">
                <div class="col-lg-6">
                    <div class="mission-badge">Our Mission</div>
                    <h2 class="section-title">Empowering Your Culinary Creativity</h2>
                    <p class="section-text">
                        At FoodFusion, we believe that cooking is more than just preparation of meals—it's an expression
                        of creativity, culture, and connection. Our mission is to inspire and empower home cooks of all
                        skill levels to explore the world of culinary arts, discover new flavors, and share their
                        passion for food with others.
                    </p>
                    <p class="section-text">
                        Whether you're a novice in the kitchen or an experienced home chef, FoodFusion provides you with
                        the resources, community, and inspiration to elevate your cooking experience and create
                        memorable dishes that bring joy to your table.
                    </p>

                    <div class="features-grid">
                        <div class="feature-item">
                            <div class="feature-icon">
                                <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24"
                                    fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"
                                    stroke-linejoin="round">
                                    <path d="M15 11h.01"></path>
                                    <path d="M11 15h.01"></path>
                                    <path d="M16 16h.01"></path>
                                    <path d="m2 16 20 6-6-20A20 20 0 0 0 2 16"></path>
                                    <path d="M5.71 17.11a17.04 17.04 0 0 1 11.4-11.4"></path>
                                </svg>
                            </div>
                            <div>
                                <h3 class="feature-title">Culinary Inspiration</h3>
                                <p class="feature-text">Discover recipes and techniques that will inspire your cooking
                                    journey.</p>
                            </div>
                        </div>
                        <div class="feature-item">
                            <div class="feature-icon">
                                <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24"
                                    fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"
                                    stroke-linejoin="round">
                                    <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path>
                                    <circle cx="9" cy="7" r="4"></circle>
                                    <path d="M23 21v-2a4 4 0 0 0-3-3.87"></path>
                                    <path d="M16 3.13a4 4 0 0 1 0 7.75"></path>
                                </svg>
                            </div>
                            <div>
                                <h3 class="feature-title">Community Connection</h3>
                                <p class="feature-text">Connect with fellow food enthusiasts and share experiences.</p>
                            </div>
                        </div>
                        <div class="feature-item">
                            <div class="feature-icon">
                                <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24"
                                    fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"
                                    stroke-linejoin="round">
                                    <circle cx="12" cy="12" r="10"></circle>
                                    <path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"></path>
                                    <path d="M2 12h20"></path>
                                </svg>
                            </div>
                            <div>
                                <h3 class="feature-title">Global Flavors</h3>
                                <p class="feature-text">Explore diverse cuisines from around the world.</p>
                            </div>
                        </div>
                        <div class="feature-item">
                            <div class="feature-icon">
                                <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24"
                                    fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"
                                    stroke-linejoin="round">
                                    <path
                                        d="M19 14c1.49-1.46 3-3.21 3-5.5A5.5 5.5 0 0 0 16.5 3c-1.76 0-3 .5-4.5 2-1.5-1.5-2.74-2-4.5-2A5.5 5.5 0 0 0 2 8.5c0 2.3 1.5 4.05 3 5.5l7 7Z">
                                    </path>
                                </svg>
                            </div>
                            <div>
                                <h3 class="feature-title">Passion for Food</h3>
                                <p class="feature-text">Cultivate your passion for cooking and culinary arts.</p>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="col-lg-6">
                    <div class="mission-image-container">
                        <img src="image/mission-image.jpg" alt="People cooking together" class="mission-image">
                        <div class="mission-image-bg"></div>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <?php
    // Assuming you have db_connection.php included
    include 'database/db_connection.php';

    // Fetch recipes from the database
    $stmt = $conn->prepare("SELECT recipe_id, name, description, photo FROM recipe");
    $stmt->execute();
    $result = $stmt->get_result();
    $stmt->close();
    ?>


    <section class="featured-recipes text-white text-center">
        <div class="container">
            <div class="section-badge">Featured</div>
            <h2 class="section-title text-white">Featured Recipes</h2>
            <p class="section-subtitle">Explore our latest and most popular culinary creations. Discover the perfect
                recipes for any occasion.</p>

            <div id="recipeCarousel" class="carousel slide" data-bs-ride="carousel">
                <div class="carousel-inner">
                    <?php
                    if ($result->num_rows > 0) {
                        $first = true; // Flag to set the first item as active
                        while ($recipe = $result->fetch_assoc()) {
                            echo "<div class='carousel-item " . ($first ? 'active' : '') . "'>";
                            echo "<img src='" . $recipe['photo'] . "' class='d-block w-100' alt='" . $recipe['name'] . "'>";
                            echo "<div class='carousel-caption'>";
                            echo "<h5>" . $recipe['name'] . "</h5>";
                            echo "<p>" . $recipe['description'] . "</p>";
                            echo "</div>";
                            echo "</div>";
                            $first = false; // Set flag to false after the first item
                        }
                    } else {
                        echo "<p>No recipes found.</p>";
                    }
                    ?>
                </div>
                <button class="carousel-control-prev" type="button" data-bs-target="#recipeCarousel"
                    data-bs-slide="prev">
                    <span class="carousel-control-prev-icon" aria-hidden="true"></span>
                    <span class="visually-hidden">Previous</span>
                </button>
                <button class="carousel-control-next" type="button" data-bs-target="#recipeCarousel"
                    data-bs-slide="next">
                    <span class="carousel-control-next-icon" aria-hidden="true"></span>
                    <span class="visually-hidden">Next</span>
                </button>
            </div>
        </div>
    </section>

    <section class="culinary-trends-section">
        <div class="container">
            <div class="section-badge">What's Hot</div>
            <h2 class="section-title">Culinary Trends</h2>
            <p class="section-subtitle">Stay ahead of the curve with the latest culinary trends. From innovative
                techniques to exciting flavor combinations, discover what's hot in the food world.</p>

            <?php
            // Assuming you have db_connection.php included
            include 'database/db_connection.php';

            // Fetch culinary trends from the database
            $stmt = $conn->prepare("SELECT culinary_id, name, description, photo FROM culinary");
            $stmt->execute();
            $result = $stmt->get_result();
            $stmt->close();
            ?>

            <div class="trends-container">
                <?php
                if ($result->num_rows > 0) {
                    while ($trend = $result->fetch_assoc()) {
                        echo "<div class='trend-item'>";
                        echo "<div class='trend-image-container'>";
                        echo "<img src='" . $trend['photo'] . "' alt='" . $trend['name'] . "'>";
                        echo "</div>";
                        echo "<div class='trend-content'>";
                        echo "<h3>" . $trend['name'] . "</h3>";
                        echo "<p>" . $trend['description'] . "</p>";
                        echo "</div>";
                        echo "</div>";
                    }
                } else {
                    echo "<p>No culinary trends found.</p>";
                }
                ?>
            </div>
        </div>
    </section>

    <section class="upcoming-events">
        <div class="container">
            <div class="section-badge">Calendar</div>
            <h2 class="section-title">Upcoming Culinary Events</h2>
            <p class="section-subtitle">Join our hands-on workshops, tastings, and culinary experiences led by
                professional chefs and food experts.</p>

            <div class="row mt-5">
                <div class="col-lg-4">
                    <div class="events-sidebar">
                        <h3>Upcoming Events</h3>
                        <div class="event-list">
                            <div class="event-list-item active" data-event="1">
                                <div>
                                    <h4>Italian Pasta Masterclass</h4>
                                    <div class="event-date">November 15, 2023</div>
                                </div>
                                <div class="event-indicator"></div>
                            </div>
                            <div class="event-list-item" data-event="2">
                                <div>
                                    <h4>Asian Street Food Festival</h4>
                                    <div class="event-date">November 22, 2023</div>
                                </div>
                                <div class="event-indicator"></div>
                            </div>
                            <div class="event-list-item" data-event="3">
                                <div>
                                    <h4>Holiday Baking Workshop</h4>
                                    <div class="event-date">December 5, 2023</div>
                                </div>
                                <div class="event-indicator"></div>
                            </div>
                        </div>
                        <button class="view-all-button">View All Events</button>
                    </div>
                </div>
                <div class="col-lg-8">
                    <div class="event-details">
                        <div class="event-detail-item active" id="event-1">
                            <div class="event-image-container">
                                <img src="image/event1.jpg" alt="Italian Pasta Masterclass">
                                <div class="event-image-overlay">
                                    <div class="event-badge">Featured Event</div>
                                    <h3>Italian Pasta Masterclass</h3>
                                </div>
                            </div>
                            <div class="event-info">
                                <p>Learn to make authentic Italian pasta from scratch with Chef Marco Rossi.</p>
                                <div class="event-meta">
                                    <div class="event-meta-item">
                                        <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20"
                                            viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
                                            stroke-linecap="round" stroke-linejoin="round">
                                            <rect width="18" height="18" x="3" y="4" rx="2" ry="2"></rect>
                                            <line x1="16" x2="16" y1="2" y2="6"></line>
                                            <line x1="8" x2="8" y1="2" y2="6"></line>
                                            <line x1="3" x2="21" y1="10" y2="10"></line>
                                        </svg>
                                        <div>
                                            <h5>Date</h5>
                                            <p>November 15, 2023</p>
                                        </div>
                                    </div>
                                    <div class="event-meta-item">
                                        <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20"
                                            viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
                                            stroke-linecap="round" stroke-linejoin="round">
                                            <circle cx="12" cy="12" r="10"></circle>
                                            <polyline points="12 6 12 12 16 14"></polyline>
                                        </svg>
                                        <div>
                                            <h5>Time</h5>
                                            <p>6:00 PM - 8:30 PM</p>
                                        </div>
                                    </div>
                                    <div class="event-meta-item">
                                        <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20"
                                            viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
                                            stroke-linecap="round" stroke-linejoin="round">
                                            <path d="M20 10c0 6-8 12-8 12s-8-6-8-12a8 8 0 0 1 16 0Z"></path>
                                            <circle cx="12" cy="10" r="3"></circle>
                                        </svg>
                                        <div>
                                            <h5>Location</h5>
                                            <p>FoodFusion Culinary Studio, New York</p>
                                        </div>
                                    </div>
                                </div>
                                <div class="event-actions">
                                    <button class="register-button">Register Now</button>
                                    <button class="calendar-button">Add to Calendar</button>
                                </div>
                            </div>
                        </div>
                        <div class="event-detail-item" id="event-2">
                            <div class="event-image-container">
                                <img src="image/event2.jpg" alt="Asian Street Food Festival">
                                <div class="event-image-overlay">
                                    <div class="event-badge">Featured Event</div>
                                    <h3>Asian Street Food Festival</h3>
                                </div>
                            </div>
                            <div class="event-info">
                                <p>Experience the vibrant flavors of Asian street food with demonstrations and tastings.
                                </p>
                                <div class="event-meta">
                                    <div class="event-meta-item">
                                        <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20"
                                            viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
                                            stroke-linecap="round" stroke-linejoin="round">
                                            <rect width="18" height="18" x="3" y="4" rx="2" ry="2"></rect>
                                            <line x1="16" x2="16" y1="2" y2="6"></line>
                                            <line x1="8" x2="8" y1="2" y2="6"></line>
                                            <line x1="3" x2="21" y1="10" y2="10"></line>
                                        </svg>
                                        <div>
                                            <h5>Date</h5>
                                            <p>November 22, 2023</p>
                                        </div>
                                    </div>
                                    <div class="event-meta-item">
                                        <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20"
                                            viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
                                            stroke-linecap="round" stroke-linejoin="round">
                                            <circle cx="12" cy="12" r="10"></circle>
                                            <polyline points="12 6 12 12 16 14"></polyline>
                                        </svg>
                                        <div>
                                            <h5>Time</h5>
                                            <p>11:00 AM - 4:00 PM</p>
                                        </div>
                                    </div>
                                    <div class="event-meta-item">
                                        <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20"
                                            viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
                                            stroke-linecap="round" stroke-linejoin="round">
                                            <path d="M20 10c0 6-8 12-8 12s-8-6-8-12a8 8 0 0 1 16 0Z"></path>
                                            <circle cx="12" cy="10" r="3"></circle>
                                        </svg>
                                        <div>
                                            <h5>Location</h5>
                                            <p>Central Park, New York</p>
                                        </div>
                                    </div>
                                </div>
                                <div class="event-actions">
                                    <button class="register-button">Register Now</button>
                                    <button class="calendar-button">Add to Calendar</button>
                                </div>
                            </div>
                        </div>
                        <div class="event-detail-item" id="event-3">
                            <div class="event-image-container">
                                <img src="image/event3.jpg" alt="Holiday Baking Workshop">
                                <div class="event-image-overlay">
                                    <div class="event-badge">Featured Event</div>
                                    <h3>Holiday Baking Workshop</h3>
                                </div>
                            </div>
                            <div class="event-info">
                                <p>Get ready for the holidays with festive baking recipes and decoration techniques.</p>
                                <div class="event-meta">
                                    <div class="event-meta-item">
                                        <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20"
                                            viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
                                            stroke-linecap="round" stroke-linejoin="round">
                                            <rect width="18" height="18" x="3" y="4" rx="2" ry="2"></rect>
                                            <line x1="16" x2="16" y1="2" y2="6"></line>
                                            <line x1="8" x2="8" y1="2" y2="6"></line>
                                            <line x1="3" x2="21" y1="10" y2="10"></line>
                                        </svg>
                                        <div>
                                            <h5>Date</h5>
                                            <p>December 5, 2023</p>
                                        </div>
                                    </div>
                                    <div class="event-meta-item">
                                        <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20"
                                            viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
                                            stroke-linecap="round" stroke-linejoin="round">
                                            <circle cx="12" cy="12" r="10"></circle>
                                            <polyline points="12 6 12 12 16 14"></polyline>
                                        </svg>
                                        <div>
                                            <h5>Time</h5>
                                            <p>3:00 PM - 5:30 PM</p>
                                        </div>
                                    </div>
                                    <div class="event-meta-item">
                                        <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20"
                                            viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
                                            stroke-linecap="round" stroke-linejoin="round">
                                            <path d="M20 10c0 6-8 12-8 12s-8-6-8-12a8 8 0 0 1 16 0Z"></path>
                                            <circle cx="12" cy="10" r="3"></circle>
                                        </svg>
                                        <div>
                                            <h5>Location</h5>
                                            <p>FoodFusion Culinary Studio, New York</p>
                                        </div>
                                    </div>
                                </div>
                                <div class="event-actions">
                                    <button class="register-button">Register Now</button>
                                    <button class="calendar-button">Add to Calendar</button>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <footer>
        <div class="container">
            <div class="footer-content">
                <div class="footer-section">
                    <h4>About Us</h4>
                    <p>Food Fusion brings together diverse food cultures and cooking expertise from around the world.
                    </p>
                </div>
                <div class="footer-section">
                    <h4>Contact Us</h4>
                    <p>Email: info@foodfusion.com</p>
                    <p>Phone: (123) 456-7890</p>
                </div>
                <div class="footer-section">
                    <h4>Follow Us</h4>
                    <div class="social-links">
                        <a href="https://www.facebook.com" target="_blank"><img src="image/facebook.png"
                                alt="Facebook"></a>
                        <a href="https://twitter.com" target="_blank"><img src="image/twitter.png" alt="Twitter"></a>
                        <a href="https://www.instagram.com" target="_blank"><img src="image/instagram.png"
                                alt="Instagram"></a>
                       
                    </div>
                </div>
                <div class="footer-section">
                    <h4>Legal</h4>
                    <ul>
                        <li><a href="privacy-policy.php">Privacy Policy</a></li>
                        <li><a href="terms.php">Terms of Service</a></li>
                    </ul>
                </div>
            </div>
            <div class="footer-bottom">
                <p>&copy; 2024 Food Fusion. All rights reserved.</p>
            </div>
        </div>
    </footer>

    <div id="cookie-consent-banner" class="cookie-consent-banner">
        <p>This website uses cookies to improve your experience. By continuing to use this site, you consent to our use
            of cookies. <a href="privacy-policy.php">Read More</a></p>
        <button id="cookie-consent-button">Accept</button>
    </div>

    <script src="bootstrap/js/bootstrap.bundle.min.js"></script>
    <script>
        document.addEventListener('DOMContentLoaded', function () {
            // Cookie consent logic
            const cookieConsentBanner = document.getElementById('cookie-consent-banner');
            const cookieConsentButton = document.getElementById('cookie-consent-button');

            // Check if the user has already accepted cookies
            if (localStorage.getItem('cookieConsent') !== 'accepted') {
                cookieConsentBanner.style.display = 'block'; // Show the banner
            }

            cookieConsentButton.addEventListener('click', function () {
                localStorage.setItem('cookieConsent', 'accepted'); // Store consent
                cookieConsentBanner.style.display = 'none'; // Hide the banner
            });

            // Registration form handling
            const registrationForm = document.getElementById('registrationForm');

            registrationForm.addEventListener('submit', (event) => {
                event.preventDefault();

                const username = document.getElementById('username').value;
                const email = document.getElementById('email').value;
                const password = document.getElementById('password').value;

                if (!username || !email || !password) {
                    alert('Please fill in all fields.');
                    return;
                }

                const formData = new URLSearchParams();
                formData.append('username', username);
                formData.append('email', email);
                formData.append('password', password);

                fetch('register.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded'
                    },
                    body: formData
                })
                    .then(response => {
                        if (!response.ok) {
                            throw new Error('Network response was not ok');
                        }
                        return response.json();
                    })
                    .then(data => {
                        console.log("Response data:", data);
                        if (data.status === "success") {
                            alert('Registration successful!');
                            registrationForm.reset();
                            window.location.href = data.redirect; // Redirect to the URL from the response
                        } else {
                            alert(data.message);
                        }
                    })
                    .catch(error => {
                        console.error('Error:', error);
                        alert('An error occurred during registration.');
                    });
            });

            // Smooth scroll for the scroll indicator
            document.querySelector('.scroll-indicator a').addEventListener('click', function (e) {
                e.preventDefault();
                const targetId = this.getAttribute('href');
                const targetElement = document.querySelector(targetId);
                if (targetElement) {
                    targetElement.scrollIntoView({
                        behavior: 'smooth'
                    });
                }
            });
        });


        
            // Event list item click handling
            const eventListItems = document.querySelectorAll('.event-list-item');
            const eventDetailItems = document.querySelectorAll('.event-detail-item');

            eventListItems.forEach(item => {
                item.addEventListener('click', function () {
                    // Remove active class from all items
                    eventListItems.forEach(el => el.classList.remove('active'));
                    eventDetailItems.forEach(el => el.classList.remove('active'));

                    // Add active class to clicked item
                    this.classList.add('active');

                    // Get event ID and show corresponding detail
                    const eventId = this.getAttribute('data-event');
                    document.getElementById('event-' + eventId).classList.add('active');
                });
            });
    </script>

    
</body>

</html>