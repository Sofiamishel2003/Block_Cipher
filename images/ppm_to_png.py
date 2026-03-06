from PIL import Image
import os

def convert(ppm_path: str, png_path: str):
    img = Image.open(ppm_path)
    img.save(png_path)

if __name__ == "__main__":
    root = os.path.dirname(os.path.abspath(__file__))
    project = os.path.dirname(root)  # carpeta del repo
    images = os.path.join(project, "images")

    files = [
        ("tux.ppm", "tux.png"),
        ("aes_ecb.ppm", "tux_ecb.png"),
        ("aes_cbc.ppm", "tux_cbc.png"),
        ("aes_ctr.ppm", "tux_ctr.png"),
    ]

    for ppm, png in files:
        ppm_path = os.path.join(images, ppm)
        png_path = os.path.join(images, png)
        convert(ppm_path, png_path)
        print(f"OK: {ppm_path} -> {png_path}")