import Header from "@/components/Header";
import Footer from "@/components/Footer";

export default function MarketingLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <>
      <div className="noise-overlay"></div>
      <div className="glow-bg"></div>
      <Header />
      {children}
      <Footer />
    </>
  );
}
