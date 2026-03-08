import Link from 'next/link';
import Image from 'next/image';

export default function Footer() {
  return (
    <footer>
        <div className="container footer-content">
            <div className="footer-left">
                <div className="logo">
                    <Image src="/assets/logo.png" alt="Chaos Kitten Logo" width={32} height={32} />
                    <span>Chaos Kitten</span>
                </div>
                <p>An open-source AI security tool for the modern web.</p>
            </div>
            <div className="footer-links">
                <Link href="#features">Features</Link>
                <Link href="#contributors">Contributors</Link>
                <a href="https://github.com/mdhaarishussain/chaos-kitten/blob/main/docs/contributing_guide.md" target="_blank" rel="noopener noreferrer">Contributing</a>
                <a href="https://github.com/mdhaarishussain/chaos-kitten/blob/main/LICENSE" target="_blank" rel="noopener noreferrer">License</a>
                <Link href="/privacy-policy" className="nav-link">Privacy Policy</Link>
                <Link href="/terms" className="nav-link">Terms of Service</Link>
            </div>
            <div className="footer-social">
                <a href="https://github.com/mdhaarishussain/chaos-kitten"><i className="fab fa-github"></i></a>
                <a href="#"><i className="fab fa-discord"></i></a>
                <a href="#"><i className="fab fa-twitter"></i></a>
            </div>
        </div>
        <div className="footer-bottom">
            <p>&copy; 2026 Apertre Open Source Program. All rights reserved.</p>
        </div>
    </footer>
  );
}
