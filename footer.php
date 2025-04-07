<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Footer</title>
    <link rel="stylesheet" href="bootstrap/css/bootstrap.min.css">
    <style>
        
/* Footer */
footer {
    background-color: #1e293b;
    
    padding: 60px 0 20px;
}

.footer-content {
    display: grid;
    grid-template-columns: repeat(1, 1fr);
    gap: 30px;
    margin-bottom: 40px;
}

@media (min-width: 576px) {
    .footer-content {
        grid-template-columns: repeat(2, 1fr);
    }
}

@media (min-width: 992px) {
    .footer-content {
        grid-template-columns: repeat(4, 1fr);
    }
}

.footer-section h4 {
    font-size: 1.2rem;
    margin-bottom: 20px;
    color: white;
}

.footer-section p {
    color: #cbd5e1;
    margin-bottom: 10px;
}

.social-links {
    display: flex;
    gap: 15px;
}

.social-links a {
    
    transition: transform 0.3s ease;
}

.social-links a:hover {
    transform: translateY(-3px);
}

.social-links img {
    width: 24px;
    height: 24px;
    border-radius: 45%;
}

.footer-section ul {
    list-style: none;
    padding: 0;
}

.footer-section ul li {
    margin-bottom: 10px;
}

.footer-section ul li a {
    color: #cbd5e1;
    text-decoration: none;
    transition: color 0.3s ease;
}

.footer-section ul li a:hover {
    color: #e3a008;
}

.footer-bottom {
    border-top: 1px solid #334155;
    padding-top: 20px;
    text-align: center;
    color: #94a3b8;
    font-size: 0.9rem;
}

/* Cookie Consent Banner */
.cookie-consent-banner {
    position: fixed;
    bottom: 0;
    left: 0;
    right: 0;
    background-color: rgba(15, 23, 42, 0.95);
    color: white;
    padding: 15px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    z-index: 1000;
    display: none;
}

.cookie-consent-banner p {
    margin: 0;
    padding-right: 20px;
}

.cookie-consent-banner a {
    color: #e3a008;
    text-decoration: none;
}

.cookie-consent-banner a:hover {
    text-decoration: underline;
}

#cookie-consent-button {
    background-color: #e3a008;
    color: white;
    border: none;
    padding: 8px 15px;
    border-radius: 5px;
    cursor: pointer;
    transition: background-color 0.3s ease;
}

#cookie-consent-button:hover {
    background-color: #c27803;
}

/* Modal Styling */
.modal-content {
    border-radius: 10px;
    overflow: hidden;
}

.modal-header {
    background: linear-gradient(to right, #1e293b, #334155);
    color: white;
    border-bottom: none;
}

.modal-title {
    font-family: 'Playfair Display', serif;
    font-weight: 700;
}

.btn-close {
    filter: brightness(0) invert(1);
}

.modal-body {
    padding: 20px;
}

.form-label {
    font-weight: 500;
    color: #475569;
}

.btn-primary {
    background-color: #e3a008;
    border-color: #e3a008;
    transition: background-color 0.3s ease;
}

.btn-primary:hover {
    background-color: #c27803;
    border-color: #c27803;
}

/* Responsive Adjustments */
@media (max-width: 768px) {
    .home-contact h1 {
        font-size: 2.5rem;
    }
    
    .carousel-item img {
        height: 350px;
    }

    .stats-container {
        gap: 20px;
    }

    .stat-number {
        font-size: 2rem;
    }
}

@media (max-width: 576px) {
    .home-contact h1 {
        font-size: 2rem;
    }

    .join-us-button {
        padding: 10px 20px;
    }

    .carousel-item img {
        height: 250px;
    }

    .stats-container {
        gap: 15px;
    }

    .stat-item {
        min-width: 40%;
    }

    .stat-number {
        font-size: 1.8rem;
    }
}
    </style>
</head>

<body>

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
                    <p>Email: foodfusionhub@gmail.com</p>
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
                        <li><a href="privacy_policy.php">Privacy Policy</a></li>
                        
                    </ul>
                </div>
            </div>
            <div class="footer-bottom">
                <p>&copy; 2024 Food Fusion. All rights reserved.</p>
            </div>
        </div>
    </footer>

</body>

</html>