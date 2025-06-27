# Maintainer: Your Name <your_email@example.com>
# Replace with your actual name and email

pkgname=helufw
pkgver=0.1.0 # Initial version, you can update this
pkgrel=1
pkgdesc="A GUI firewall manager for UFW, built with PyQt5"
arch=('any') # Python apps can often run on any architecture
url="https://github.com/helwan-linux/helufw"
license=('GPL3') # Or whatever license your project uses
depends=('python' 'python-pyqt5' 'ufw' 'polkit') # Corrected policykit to polkit
makedepends=('git') # To clone the repository if needed, though we're using source
source=("$pkgname::git+$url.git#branch=main") # Or use a specific tag/commit
sha256sums=('SKIP') # Use SKIP for git sources, or calculate for specific tarballs

build() {
  # No compilation needed for Python scripts, so this can be empty or print a message
  echo "No build steps required for Python application."
}

package() {
  # Create the target directory for the application files
  # This is where your main Python script and icon will go
  install -d "$pkgdir/opt/$pkgname"

  # Copy application files to the designated directory
  # The files are inside a folder named 'HelUfw' within the cloned repo
  # We need to copy the *contents* of that HelUfw folder
  cp -r "$srcdir/$pkgname/HelUfw/"* "$pkgdir/opt/$pkgname/"

  # --- Desktop Entry ---
  # Install the .desktop file for application launcher integration
  install -d "$pkgdir/usr/share/applications/"
  install -m644 "$pkgdir/opt/$pkgname/helufw.desktop" "$pkgdir/usr/share/applications/"

  # Update the Exec line in the .desktop file to point to the correct path
  # And ensure it's executed with python3
  sed -i 's|^Exec=.*|Exec=python3 /opt/helufw/helufw.py|' "$pkgdir/usr/share/applications/helufw.desktop"

  # --- Icon ---
  # Install the icon
  # Assume the icon is located in the HelUfw folder and named helufw_icon.png
  # We typically use /usr/share/pixmaps for general icons or specific hicolor if multiple sizes
  install -d "$pkgdir/usr/share/pixmaps/"
  install -m644 "$pkgdir/opt/$pkgname/helufw_icon.png" "$pkgdir/usr/share/pixmaps/"

  # Update the Icon line in the .desktop file to point to the installed icon
  sed -i 's|^Icon=.*|Icon=helufw_icon|' "$pkgdir/usr/share/applications/helufw.desktop"
  # Note: we use just the name 'helufw_icon' here because /usr/share/pixmaps is in the default icon search path.

  # --- Set execute permissions for the Python script first ---
  chmod +x "$pkgdir/opt/$pkgname/helufw.py"

  # --- Then create Symlink for easy execution from PATH ---
  # Create a symbolic link in /usr/bin to easily run the app from terminal
  install -d "$pkgdir/usr/bin/"
  ln -sf "/opt/$pkgname/helufw.py" "$pkgdir/usr/bin/helufw"
}
