// Home page animations and interactions

document.addEventListener('DOMContentLoaded', () => {
    initializeAnimations();
    initializeCardHovers();
});

function initializeAnimations() {
    // Animate hero section on load
    const hero = document.querySelector('.hero-section');
    if (hero) {
        hero.style.opacity = '0';
        hero.style.transform = 'translateY(20px)';
        
        setTimeout(() => {
            hero.style.transition = 'all 0.8s ease-out';
            hero.style.opacity = '1';
            hero.style.transform = 'translateY(0)';
        }, 100);
    }

    // Animate feature cards with stagger
    const cards = document.querySelectorAll('.feature-card');
    cards.forEach((card, index) => {
        card.style.opacity = '0';
        card.style.transform = 'translateY(30px)';
        
        setTimeout(() => {
            card.style.transition = 'all 0.6s ease-out';
            card.style.opacity = '1';
            card.style.transform = 'translateY(0)';
        }, 300 + (index * 150));
    });

    // Animate info section
    const infoSection = document.querySelector('.info-section');
    if (infoSection) {
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.style.opacity = '1';
                    entry.target.style.transform = 'translateY(0)';
                }
            });
        }, { threshold: 0.1 });

        infoSection.style.opacity = '0';
        infoSection.style.transform = 'translateY(30px)';
        infoSection.style.transition = 'all 0.8s ease-out';
        observer.observe(infoSection);
    }
}

function initializeCardHovers() {
    const cards = document.querySelectorAll('.feature-card');
    
    cards.forEach(card => {
        card.addEventListener('mouseenter', () => {
            card.style.transform = 'translateY(-10px) scale(1.02)';
        });
        
        card.addEventListener('mouseleave', () => {
            card.style.transform = 'translateY(0) scale(1)';
        });
    });

    // Button hover effects
    const buttons = document.querySelectorAll('.card-button');
    buttons.forEach(button => {
        button.addEventListener('mouseenter', () => {
            const arrow = button.querySelector('.arrow');
            if (arrow) {
                arrow.style.transform = 'translateX(5px)';
            }
        });
        
        button.addEventListener('mouseleave', () => {
            const arrow = button.querySelector('.arrow');
            if (arrow) {
                arrow.style.transform = 'translateX(0)';
            }
        });
    });
}

// Add floating badge animation
const badges = document.querySelectorAll('.badge');
badges.forEach((badge, index) => {
    badge.style.animation = `float 3s ease-in-out ${index * 0.2}s infinite`;
});

// Add keyframe animation dynamically
const style = document.createElement('style');
style.textContent = `
    @keyframes float {
        0%, 100% { transform: translateY(0px); }
        50% { transform: translateY(-5px); }
    }
`;
document.head.appendChild(style);
