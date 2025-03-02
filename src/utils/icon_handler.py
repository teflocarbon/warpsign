from pathlib import Path
import shutil
from uuid import uuid4
from typing import Dict
import plistlib
from logger import get_console

try:
    from PIL import Image
except ImportError:
    Image = None


class IconHandler:
    def __init__(self):
        self.console = get_console()

    # Thanks to asdfzxcvbn for the original implementation from cyan!
    # It saved me digging through the Info.plist.

    def update_app_icon(self, app_dir: Path, icon_path: Path, info_plist: Dict) -> bool:
        """Update app icon with a new image"""
        if Image is None:
            self.console.print(
                "[yellow]Warning: Pillow is not installed, icon change not available"
            )
            self.console.print("[yellow]Hint: pip install pillow")
            return False

        if not icon_path.exists():
            self.console.print(f"[red]Error: Icon file not found: {icon_path}")
            return False

        try:
            # Generate unique identifier for icon files
            uid = f"cyan_{uuid4().hex[:7]}a"  # can't end with number
            i60 = f"{uid}60x60"
            i76 = f"{uid}76x76"

            # Create resized icons
            with Image.open(icon_path) as img:
                # iPhone icons (120x120 and 180x180)
                img.resize((120, 120)).save(app_dir / f"{i60}@2x.png", "PNG")
                img.resize((180, 180)).save(app_dir / f"{i60}@3x.png", "PNG")
                # iPad icons (152x152 and 167x167)
                img.resize((152, 152)).save(app_dir / f"{i76}@2x~ipad.png", "PNG")
                img.resize((167, 167)).save(app_dir / f"{i76}@2.17x~ipad.png", "PNG")

            self.console.print("[green]Generated resized app icons")

            # Update Info.plist icon entries
            if "CFBundleIcons" not in info_plist:
                info_plist["CFBundleIcons"] = {}
            if "CFBundleIcons~ipad" not in info_plist:
                info_plist["CFBundleIcons~ipad"] = {}

            # iPhone icons
            info_plist["CFBundleIcons"]["CFBundlePrimaryIcon"] = {
                "CFBundleIconFiles": [i60],
                "CFBundleIconName": uid,
            }

            # iPad icons
            info_plist["CFBundleIcons~ipad"]["CFBundlePrimaryIcon"] = {
                "CFBundleIconFiles": [i60, i76],
                "CFBundleIconName": uid,
            }

            self.console.print("[green]Updated icon configuration in Info.plist")
            return True

        except Exception as e:
            self.console.print(f"[red]Error updating app icon: {str(e)}")
            return False
